"""Investigation Case helpers — pure building blocks for the case surfaces.

Holds the STIX 2.1 bundle builders shared by entity- and case-scope exports, the case
findings roll-up, the case-list triage rows, and the Overview pivot suggestions.
Pure-Python module: no FastAPI, no Huey, no async DB. Callers prepare the entity / job-link
sets and pass them in.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime

from app.constants import SEVERITY_ORDER, SEVERITY_RANK
from app.intel.tactics import _MITRE_TACTIC_COLORS, _MITRE_TACTICS
from app.models import AnalysisJob, Entity, EntityJobLink, InvestigationCase

# STIX 2.1 pattern templates per entity type. Read only through `stix_pattern`, which the
# IOC pack, the entity/case bundle builders and the /intel/ioc-feed STIX branch all call.
STIX_PATTERNS: dict[str, str] = {
    "ip_address": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "hash": "[file:hashes.'SHA-256' = '{value}']",
    "user": "[user-account:account_login = '{value}']",
    "executable": "[file:name = '{value}']",
    "computer": "[x-logstotal-host:hostname = '{value}']",
    "service": "[software:name = '{value}']",
    "task": "[x-logstotal-task:name = '{value}']",
    "cmdline_file": "[file:name = '{value}']",
}

# `file:hashes` keys by digest length — the table `misp._HASH_RES` classifies with too.
_HASH_KEY_BY_LENGTH = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}


def stix_pattern(entity_type: str, value: str | None) -> str:
    """The STIX 2.1 pattern for one entity value. The one builder every export uses.

    `STIX_PATTERNS` alone labelled every hash SHA-256 and every IP ipv4-addr, so an MD5 was
    compared against SHA-256 values downstream and never matched. And a pattern string
    literal allows only `\\` and `\'` as escapes: escaping just the quote let a trailing
    backslash (every Windows task path) swallow the closing quote, and the receiving TIP
    rejected the indicator — or the whole bundle.
    """
    value = value or ""
    literal = value.replace("\\", "\\\\").replace("'", "\\'")
    if entity_type == "hash":
        key = _HASH_KEY_BY_LENGTH.get(len(value))
        if key:
            return f"[file:hashes.'{key}' = '{literal}']"
    if entity_type == "ip_address":
        try:
            if ipaddress.ip_address(value).version == 6:
                return f"[ipv6-addr:value = '{literal}']"
        except ValueError:
            pass
    return STIX_PATTERNS.get(entity_type, "[x-logstotal:value = '{value}']").format(value=literal)


LOGSTOTAL_IDENTITY_ID = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'logstotal')}"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_dt(dt: datetime | None, fallback: str) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else fallback


def make_identity(now: str | None = None) -> dict:
    """LogsTotal identity object — stable UUID, safe to include once per bundle."""
    now = now or _now_iso()
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": LOGSTOTAL_IDENTITY_ID,
        "created": now,
        "modified": now,
        "name": "LogsTotal",
        "identity_class": "system",
    }


def make_indicator(entity: Entity, now: str | None = None) -> dict:
    """STIX 2.1 indicator object for a single entity. Deterministic ID (uuid5)."""
    now = now or _now_iso()
    iid = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'logstotal:entity:{entity.id}')}"
    pattern = stix_pattern(entity.entity_type, entity.value)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": iid,
        "created": now,
        "modified": now,
        "name": entity.value,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": _format_dt(entity.first_seen_at, now),
        "labels": [entity.entity_type],
        "created_by_ref": LOGSTOTAL_IDENTITY_ID,
    }


def make_relationship(source_id: str, target_id: str, *, kind: str = "related-to", now: str | None = None) -> dict:
    """STIX 2.1 relationship object. Deterministic ID derived from source/target."""
    now = now or _now_iso()
    rel_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"logstotal:rel:{source_id}:{target_id}:{kind}")
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{rel_uuid}",
        "created": now,
        "modified": now,
        "relationship_type": kind,
        "source_ref": source_id,
        "target_ref": target_id,
    }


def make_sighting(target_indicator_id: str, job: AnalysisJob, *, count: int = 1, now: str | None = None) -> dict:
    """STIX 2.1 sighting linking a job (observation event) to an indicator."""
    now = now or _now_iso()
    sighting_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"logstotal:sighting:{target_indicator_id}:{job.id}")
    return {
        "type": "sighting",
        "spec_version": "2.1",
        "id": f"sighting--{sighting_uuid}",
        "created": now,
        "modified": now,
        "sighting_of_ref": target_indicator_id,
        "first_seen": _format_dt(job.created_at, now),
        "count": max(1, count),
        "created_by_ref": LOGSTOTAL_IDENTITY_ID,
    }


def wrap_bundle(objects: list[dict]) -> dict:
    """Wrap a list of STIX objects in a bundle envelope with a fresh bundle ID."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def build_entity_stix_bundle(
    focal: Entity,
    neighbors: Iterable[Entity],
    job_links: Iterable[EntityJobLink],
) -> dict:
    """Assemble the STIX bundle for a single focal entity with its co-occurring neighbors and sightings."""
    now = _now_iso()
    identity = make_identity(now)
    focal_ind = make_indicator(focal, now)

    objects: list[dict] = [identity, focal_ind]

    neighbor_ind_by_id: dict[int, str] = {}
    for n in neighbors:
        ind = make_indicator(n, now)
        objects.append(ind)
        neighbor_ind_by_id[n.id] = ind["id"]

    for n in neighbors:
        objects.append(make_relationship(focal_ind["id"], neighbor_ind_by_id[n.id], now=now))

    for jl in job_links:
        job = jl.job
        if not job:
            continue
        objects.append(make_sighting(focal_ind["id"], job, count=jl.occurrence_count or 1, now=now))

    return wrap_bundle(objects)


def build_case_stix_bundle(
    case_name: str,
    entities: Iterable[Entity],
    job_links_by_entity: dict[int, list[EntityJobLink]],
    *,
    case_id: int | None = None,
) -> dict:
    """Assemble the STIX bundle for a Case: each member entity is an indicator, sightings come from
    each entity's job links within the case scope.

    `job_links_by_entity` maps Entity.id → list of EntityJobLink rows whose `job_id` is in the case.
    """
    now = _now_iso()
    identity = make_identity(now)
    objects: list[dict] = [identity]

    # Optional case-level note
    # Keyed on the case, not its name: two cases called "Phishing" must not overwrite each
    # other's note in a TIP, and renaming a case must not orphan the note it already has.
    note_seed = f"logstotal:case-id:{case_id}" if case_id is not None else f"logstotal:case:{case_name}"
    case_note_id = f"note--{uuid.uuid5(uuid.NAMESPACE_URL, note_seed)}"
    objects.append(
        {
            "type": "note",
            "spec_version": "2.1",
            "id": case_note_id,
            "created": now,
            "modified": now,
            "abstract": f"LogsTotal Investigation Case: {case_name}",
            "content": case_name,
            "object_refs": [],  # filled in below
            "created_by_ref": LOGSTOTAL_IDENTITY_ID,
        }
    )

    entity_ind_by_id: dict[int, str] = {}
    for e in entities:
        ind = make_indicator(e, now)
        objects.append(ind)
        entity_ind_by_id[e.id] = ind["id"]

    objects[1]["object_refs"] = list(entity_ind_by_id.values())

    for ent_id, links in job_links_by_entity.items():
        target_ind = entity_ind_by_id.get(ent_id)
        if not target_ind:
            continue
        for jl in links:
            job = jl.job
            if not job:
                continue
            objects.append(make_sighting(target_ind, job, count=jl.occurrence_count or 1, now=now))

    return wrap_bundle(objects)


# ── Case findings roll-up (Overview tab) ───────────────────────────────────────────


def suggest_case_severity(severity_counts: dict[str, int]) -> str | None:
    """Worst severity present with a nonzero count, per the canonical `SEVERITY_ORDER`.

    An empty mapping (or one where every count is zero) returns `None`. Keys outside
    `SEVERITY_ORDER` are ignored — this only ever walks the canonical list, never the
    input dict's own keys.
    """
    for severity in SEVERITY_ORDER:
        if (severity_counts.get(severity) or 0) > 0:
            return severity
    return None


def build_findings_rollup(
    severity_rows: Iterable[tuple[str, int, int]],
    rule_rows: Iterable[tuple[str, str, int]],
    tactic_counts: dict[str, int],
) -> dict:
    """Assemble the template-ready dict for `intel/partials/_case_summary.html`.

    Args:
        severity_rows: `(severity, findings_count, events_sum)` — one row per severity
            present in the case's jobs (e.g. from a `GROUP BY Finding.severity` query).
            Rows with a non-positive `findings_count`, or a severity outside
            `SEVERITY_ORDER`, are dropped.
        rule_rows: `(rule_name, severity, events_sum)` for the top rules, already
            ordered and capped by the caller (worst-severity-first, then event count
            descending) — passed through as-is, just reshaped into dicts.
        tactic_counts: `{tactic: event_count}` already resolved against the canonical
            MITRE tactic list (see `app.intel.tactics`); only positive counts render.
    """
    by_severity: dict[str, tuple[int, int]] = {}
    for severity, findings_count, events_sum in severity_rows:
        if severity not in SEVERITY_ORDER:
            continue
        findings_count = findings_count or 0
        if findings_count <= 0:
            continue
        by_severity[severity] = (findings_count, events_sum or 0)

    severities = [{"severity": s, "findings": by_severity[s][0], "events": by_severity[s][1]} for s in SEVERITY_ORDER if s in by_severity]
    total_findings = sum(v[0] for v in by_severity.values())
    total_events = sum(v[1] for v in by_severity.values())
    suggested_severity = suggest_case_severity({s: v[0] for s, v in by_severity.items()})

    top_rules = [{"rule_name": rule_name, "severity": severity, "events": events or 0} for rule_name, severity, events in rule_rows]

    tactics = [{"tactic": t, "count": tactic_counts[t], "color": _MITRE_TACTIC_COLORS[t]} for t in _MITRE_TACTICS if tactic_counts.get(t, 0) > 0]

    return {
        "severities": severities,
        "total_findings": total_findings,
        "total_events": total_events,
        "suggested_severity": suggested_severity,
        "top_rules": top_rules,
        "tactics": tactics,
    }


# ── Case list triage ──────────────────────────────────────────────────────────


def _as_naive_utc(dt: datetime | None) -> datetime | None:
    """Strip tzinfo (converting to UTC first) so datetimes from different sources compare
    safely — mirrors `templates_config._time_ago`'s normalization. Purely defensive: the
    columns/aggregates `_latest_activity` compares here (`updated_at`, `CaseJobLink`/
    `CaseEntityLink.added_at`) are naive UTC by convention, but callers and DB backends
    aren't required to agree on that — a comparison mixing a naive and a timezone-aware
    datetime would otherwise raise `TypeError` instead of just sorting correctly."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def _latest_activity(*candidates: datetime | None) -> datetime | None:
    """Max of the given datetimes (any may be `None`), compared as naive UTC. `None` if
    every candidate is `None`."""
    present = [c for c in candidates if c is not None]
    if not present:
        return None
    return max(present, key=_as_naive_utc)


def build_case_list_rows(
    cases: Iterable[InvestigationCase],
    severity_counts_by_case: dict[int, dict[str, int]],
    job_activity: dict[int, datetime],
    entity_activity: dict[int, datetime],
    sort: str,
) -> list[dict]:
    """Assemble triage-ready rows for the cases list page.

    Each row is ``{"case": case, "findings_total": int, "derived_severity": str | None,
    "last_activity": datetime | None}``. ``severity_counts_by_case`` must already be
    privacy-filtered by the caller's SQL (`visible_job_filter` — see
    `routers/cases.py::cases_list`) so a private job linked into a shared case never
    contributes to another viewer's findings total or derived severity. ``last_activity``
    is ``max(job_activity.get(case.id), entity_activity.get(case.id), case.updated_at)`` —
    a case is never "less active" than its own `updated_at`, and a link added after the
    case row itself was last touched (e.g. re-adding an existing job) is still picked up.

    ``sort`` re-orders the already-loaded (<=200 row) list purely in Python; the caller's
    SQL order (`updated_at desc`) is preserved for ``"updated"`` or any value this function
    doesn't recognize — an invalid `sort` never raises:

    - ``"activity"`` — `last_activity` descending (missing values sort last).
    - ``"findings"`` — `findings_total` descending.
    - ``"name"`` — case-insensitive ascending.
    - ``"severity"`` — worst derived severity first (via `SEVERITY_RANK`), cases with no
      derived severity last, ties broken by `updated_at` descending.
    """
    rows: list[dict] = []
    for case in cases:
        counts = severity_counts_by_case.get(case.id) or {}
        findings_total = sum(counts.values())
        derived_severity = suggest_case_severity(counts)
        last_activity = _latest_activity(job_activity.get(case.id), entity_activity.get(case.id), case.updated_at)
        rows.append(
            {
                "case": case,
                "findings_total": findings_total,
                "derived_severity": derived_severity,
                "last_activity": last_activity,
            }
        )

    if sort == "activity":
        rows.sort(key=lambda r: _as_naive_utc(r["last_activity"]) or datetime.min, reverse=True)
    elif sort == "findings":
        rows.sort(key=lambda r: r["findings_total"], reverse=True)
    elif sort == "name":
        rows.sort(key=lambda r: (r["case"].name or "").lower())
    elif sort == "severity":
        # Stable two-pass sort: Python's sort is stable, so the updated_at-desc order from
        # the first pass survives as the tie-break within each severity-rank bucket.
        rows.sort(key=lambda r: _as_naive_utc(r["case"].updated_at) or datetime.min, reverse=True)
        rows.sort(key=lambda r: SEVERITY_RANK.get(r["derived_severity"], len(SEVERITY_RANK)))
    # "updated" (or anything unrecognized) keeps the caller's incoming order.
    return rows


# ── Pivot suggestions (Overview tab) ───────────────────────────────────────────────


def build_similar_pivot_rows(candidates: Iterable[tuple[int, object]], exclude_job_ids: set[int], cap: int = 8) -> list[dict]:
    """Reduce TLSH neighbor candidates gathered across several source case jobs into
    pivot-ready rows for the Overview tab's "Similar files" section.

    ``candidates`` is an iterable of ``(source_job_id, SimilarFile)`` pairs — one entry per
    neighbor ``find_similar_files_async`` returned for a given source job (see
    ``routers/cases.py::_build_case_pivots``, which probes up to the 10 most recent visible
    case jobs that have a TLSH hash). A candidate is dropped when its own job is already a
    case member (``exclude_job_ids``) or it has no attached job at all (nothing to add).
    Remaining candidates are deduped by target job id, keeping the lowest-distance
    occurrence (and the source job that produced it), then sorted by distance ascending and
    capped at ``cap``.
    """
    best: dict[int, tuple[int, object]] = {}
    for source_job_id, sf in candidates:
        if sf.job_id is None or sf.job_id in exclude_job_ids:
            continue
        current = best.get(sf.job_id)
        if current is None or sf.distance < current[1].distance:
            best[sf.job_id] = (source_job_id, sf)

    rows = [{"filename": sf.original_filename, "distance": sf.distance, "source_job_id": source_job_id, "target_job_id": sf.job_id} for source_job_id, sf in best.values()]
    rows.sort(key=lambda r: r["distance"])
    return rows[:cap]


def merge_correlated_hit(rows_by_job: dict[int, dict], job_id: int, filename: str, severity: str, rule_signature: str) -> None:
    """Fold one correlated-finding hit into the running per-job accumulator for the
    Overview tab's "Correlated findings" section — mutates ``rows_by_job`` in place.

    Tracks the worst severity seen for that job (via ``SEVERITY_RANK``) and the *set* of
    distinct ``rule_signature``s seen — ``count`` is the number of distinct signatures, not
    the number of hits folded in, so a job with duplicate Finding rows sharing one
    signature (e.g. re-run duplicates) doesn't overstate "N rules". The signature set is
    internal bookkeeping only; :func:`rank_correlated_pivot_rows` projects it away before
    the rows reach a template.
    """
    row = rows_by_job.setdefault(job_id, {"job_id": job_id, "filename": filename, "count": 0, "worst_severity": severity, "_signatures": set()})
    row["_signatures"].add(rule_signature)
    row["count"] = len(row["_signatures"])
    if SEVERITY_RANK.get(severity, len(SEVERITY_RANK)) < SEVERITY_RANK.get(row["worst_severity"], len(SEVERITY_RANK)):
        row["worst_severity"] = severity


def rank_correlated_pivot_rows(rows_by_job: dict[int, dict], cap: int = 10) -> list[dict]:
    """Order the per-job rows accumulated by :func:`merge_correlated_hit` worst-severity-first
    (ties broken by match count descending) and cap at ``cap``.

    Projects each row down to the public ``{job_id, filename, count, worst_severity}``
    shape — drops the internal ``_signatures`` bookkeeping set so callers and templates see
    only the public row shape.
    """
    rows = [{"job_id": r["job_id"], "filename": r["filename"], "count": r["count"], "worst_severity": r["worst_severity"]} for r in rows_by_job.values()]
    rows.sort(key=lambda r: (SEVERITY_RANK.get(r["worst_severity"], len(SEVERITY_RANK)), -r["count"]))
    return rows[:cap]
