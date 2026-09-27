"""Typed entity relationships — first-class evidence-backed edges between entities.

Pure extraction layer (no FastAPI / Huey imports, same discipline as
``app/similarity/``). The extractors produce entity *values* normalized exactly
like ``_compute_analytics_data`` in ``app/analytics.py`` so the resulting
tuples line up with the ``entity_map`` keys ``(value, entity_type)`` that
``persist_entities_from_analytics`` already builds. Any tuple whose endpoints
are not present in that map is silently dropped at persist time — so extraction
can be liberal without ever creating dangling edges.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import NamedTuple

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

# Shared observable patterns (compiled once in app.constants, which is FastAPI-free).
from app.constants import RE_DOMAIN as _RE_DOMAIN
from app.constants import RE_HASH as _RE_HASH
from app.constants import RE_IPV4 as _RE_IPV4

_UPSERT_BATCH = 200

_JUNK_BASENAMES = frozenset(("-", "?", ".", ".."))

# Max sample events retained per edge per job (keeps evidence rows small).
EVIDENCE_CAP = 3

# Whitelist of fields kept in a relationship evidence sample: the EVTX/auditd fields
# the extractors read, plus timestamp/host and process context (pid, ppid, syscall,
# proctitle, terminal, ...), so samples stay compact rather than storing whole raw
# events. Not an exact mirror of the extractor field set — the Security 4688 spellings
# (NewProcessName, ProcessName, ParentProcessName) are read but not sampled.
EVIDENCE_FIELDS: tuple[str, ...] = (
    "UtcTime",
    "Timestamp",
    "SystemTime",
    "Computer",
    "EventID",
    "Image",
    "ParentImage",
    "ImageLoaded",
    "Hashes",
    "Hash",
    "User",
    "QueryName",
    "QueryResults",
    "TargetUserName",
    "IpAddress",
    "SourceIp",
    "DestinationIp",
    "TargetFilename",
    # Auditd / Linux (flat Zircolite output)
    "exe",
    "comm",
    "proctitle",
    "acct",
    "uid",
    "auid",
    "pid",
    "ppid",
    "addr",
    "syscall",
    "key",
    "terminal",
    "hostname",
    "node",
    "name",
    "nametype",
    "a0",
    "a1",
)

# Host-identifying fields, in lookup order: EVTX `Computer` first, then the
# Linux/syslog/journald spellings. Mirror of the analytics `hostname_keys` bucket.
_HOSTNAME_KEYS: tuple[str, ...] = ("Computer", "hostname", "node", "host", "_HOSTNAME")

# Placeholder host values that are not real machines. Zircolite emits
# host="offline" when parsing a log with no host context (auditd/EVTX offline mode).
_HOST_NOISE: frozenset[str] = frozenset({"offline", "-", "n/a", "unknown"})

# Canonical relationship types. Directed source -> target. The dashboard filter
# and graph legend read this list, so keep it the single source of truth.
RELATIONSHIP_TYPES: tuple[str, ...] = (
    "hashes_to",  # executable -> hash
    "resolves_to",  # domain -> ip_address
    "parent_of",  # executable -> executable
    "runs_as",  # executable -> user
    "runs_on",  # executable -> computer
    "logs_on_from",  # user -> ip_address
    "logs_on_to",  # user -> computer
    "connects_to",  # ip_address -> ip_address
    "loads",  # executable -> executable
    "creates",  # executable -> cmdline_file
    "communicates_with",  # executable -> ip_address (auditd: one-sided socket addr)
)

# Human-readable labels for the UI.
RELATIONSHIP_LABELS: dict[str, str] = {
    "hashes_to": "hashes to",
    "resolves_to": "resolves to",
    "parent_of": "parent of",
    "runs_as": "runs as",
    "runs_on": "runs on",
    "logs_on_from": "logs on from",
    "logs_on_to": "logs on to",
    "connects_to": "connects to",
    "loads": "loads",
    "creates": "creates",
    "communicates_with": "communicates with",
}

# Canonical endpoint entity types per relationship: rel_type -> (source_type, target_type).
RELATIONSHIP_ENDPOINTS: dict[str, tuple[str, str]] = {
    "hashes_to": ("executable", "hash"),
    "resolves_to": ("domain", "ip_address"),
    "parent_of": ("executable", "executable"),
    "runs_as": ("executable", "user"),
    "runs_on": ("executable", "computer"),
    "logs_on_from": ("user", "ip_address"),
    "logs_on_to": ("user", "computer"),
    "connects_to": ("ip_address", "ip_address"),
    "loads": ("executable", "executable"),
    "creates": ("executable", "cmdline_file"),
    "communicates_with": ("executable", "ip_address"),
}


class AssociationSpec(NamedTuple):
    """One curated association group on the entity Overview card."""

    rel_type: str
    direction: str  # "out" = focal entity is the edge source; "in" = focal is the target
    label: str  # group heading on the Overview card


# Curated per-entity-type associations surfaced on the Overview tab
# ("Associated Entities" card): a hash's filenames, an IP's domains, etc.
# service / task intentionally absent: no relationship type touches them.
ASSOCIATIONS: dict[str, tuple[AssociationSpec, ...]] = {
    "executable": (
        AssociationSpec("hashes_to", "out", "Hashes"),
        AssociationSpec("parent_of", "in", "Parent processes"),
        AssociationSpec("parent_of", "out", "Child processes"),
        AssociationSpec("creates", "out", "Created files"),
        AssociationSpec("loads", "out", "Loaded modules"),
        AssociationSpec("loads", "in", "Loaded by"),
        AssociationSpec("runs_as", "out", "Run by users"),
        AssociationSpec("runs_on", "out", "Seen on hosts"),
        AssociationSpec("communicates_with", "out", "Network peers"),
    ),
    "hash": (AssociationSpec("hashes_to", "in", "Filenames"),),
    "domain": (AssociationSpec("resolves_to", "out", "Resolves to"),),
    "ip_address": (
        AssociationSpec("resolves_to", "in", "Domains"),
        AssociationSpec("logs_on_from", "in", "Logons from this IP"),
        AssociationSpec("connects_to", "out", "Connects to"),
        AssociationSpec("connects_to", "in", "Inbound connections"),
        AssociationSpec("communicates_with", "in", "Contacted by"),
    ),
    "user": (
        AssociationSpec("logs_on_to", "out", "Computers"),
        AssociationSpec("logs_on_from", "out", "Logon source IPs"),
        AssociationSpec("runs_as", "in", "Executables"),
    ),
    "computer": (
        AssociationSpec("logs_on_to", "in", "Users"),
        AssociationSpec("runs_on", "in", "Executables"),
    ),
    "cmdline_file": (AssociationSpec("creates", "in", "Created by"),),
}


def build_association_groups(entity_type: str, rows_by_direction: dict[str, list]) -> list[dict]:
    """Arrange fetched association rows into the curated, ordered Overview groups.

    ``rows_by_direction`` maps ``"out"``/``"in"`` to rows of
    ``(rel_type, occurrence_count, group_total, other_entity)`` — rows are
    already capped per group by the caller, ``group_total`` is the uncapped
    edge count for that group. Returns dicts ``{label, rel_type, direction,
    rows: [{entity, occurrence_count}], overflow}`` in ``ASSOCIATIONS`` spec
    order, omitting empty groups; unknown entity types yield ``[]``.
    """
    buckets: dict[tuple[str, str], dict] = {}
    for direction, rows in rows_by_direction.items():
        for rel_type, occurrence_count, group_total, other in rows:
            bucket = buckets.setdefault((rel_type, direction), {"rows": [], "total": group_total})
            bucket["rows"].append({"entity": other, "occurrence_count": occurrence_count})

    groups: list[dict] = []
    for spec in ASSOCIATIONS.get(entity_type, ()):
        bucket = buckets.get((spec.rel_type, spec.direction))
        if not bucket or not bucket["rows"]:
            continue
        groups.append(
            {
                "label": spec.label,
                "rel_type": spec.rel_type,
                "direction": spec.direction,
                "rows": bucket["rows"],
                "overflow": max(0, bucket["total"] - len(bucket["rows"])),
            }
        )
    return groups


# ── Normalizers (mirror _compute_analytics_data) ───────────────────────────


def _norm_exe(val: object) -> str | None:
    """Basename, backslashes folded, lowercased — matches the ``executable`` entity rule."""
    if not isinstance(val, str):
        return None
    name = os.path.basename(val.replace("\\", "/")).strip().lower()
    if len(name) > 1 and name not in _JUNK_BASENAMES:
        return name
    return None


def _norm_basename(val: object) -> str | None:
    """Basename lowercased — used for ``cmdline_file`` targets (e.g. Sysmon 11 TargetFilename)."""
    if not isinstance(val, str):
        return None
    name = os.path.basename(val.replace("\\", "/")).strip().lower()
    if len(name) > 1 and name not in _JUNK_BASENAMES and "." in name:
        return name
    return None


def _norm_user(val: object) -> str | None:
    """Stripped user; machine accounts (trailing ``$``) and empties dropped.

    Noise users (system/guest/...) are intentionally *not* filtered here — if such
    a value never became an entity, ``persist_relationships`` drops the edge anyway.
    """
    if not isinstance(val, str):
        return None
    v = val.strip()
    if not v or v.endswith("$"):
        return None
    return v


def _norm_domain(val: object) -> str | None:
    """Stripped + lowercased domain; rejects values that look like IPs."""
    if not isinstance(val, str):
        return None
    v = val.strip().lower()
    if not v or "." not in v:
        return None
    if _RE_IPV4.fullmatch(v) or ":" in v:
        return None
    if _RE_DOMAIN.fullmatch(v):
        return v
    return None


def _norm_computer(val: object) -> str | None:
    """Stripped computer name (case preserved — matches the ``computer`` entity rule).

    Placeholder hosts (Zircolite's ``offline`` sentinel, ``-``) are dropped so they
    never become spurious ``computer`` entities or ``runs_on`` edges.
    """
    if not isinstance(val, str):
        return None
    v = val.strip()
    if not v or v.lower() in _HOST_NOISE:
        return None
    return v


def _norm_ip(val: object) -> str | None:
    """Return a valid IPv4/IPv6 string, else None. ``-`` and blanks are rejected."""
    if not isinstance(val, str):
        return None
    v = val.strip()
    if not v or v == "-":
        return None
    if _RE_IPV4.fullmatch(v):
        return v
    if ":" in v:
        try:
            ipaddress.IPv6Address(v)
            return v
        except ValueError:
            return None
    return None


def _extract_hashes(val: object) -> list[str]:
    """Uppercase hex hashes from a Sysmon ``MD5=..,SHA256=..`` composite or a bare hex value."""
    if not isinstance(val, str):
        return []
    s = val.strip()
    if not s:
        return []
    out: list[str] = []
    if "=" in s:
        for part in s.split(","):
            part = part.strip()
            if "=" in part:
                _, hv = part.split("=", 1)
                hv = hv.strip()
                if _RE_HASH.fullmatch(hv):
                    out.append(hv.upper())
    elif _RE_HASH.fullmatch(s):
        out.append(s.upper())
    return list(dict.fromkeys(out))


def _looks_external(ip: str) -> bool:
    """True for routable public addresses (drops private/loopback/link-local/multicast/reserved)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


# ── Event surface parsing ──────────────────────────────────────────────────


def parse_sysmon_query_results(raw: str) -> list[str]:
    """Parse the Sysmon EID 22 ``QueryResults`` column into a de-duplicated IP list.

    Format is ``type:  N value;type:  N value;`` where values may be IPv4,
    IPv6, IPv4-mapped IPv6 (``::ffff:1.2.3.4``) or CNAME hostnames. Hostnames and
    the ``::`` "no answer" placeholder are dropped; only IP strings are returned.
    """
    if not isinstance(raw, str):
        return []
    out: list[str] = []
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        if entry.lower().startswith("type:"):
            parts = entry.split()
            entry = parts[-1] if parts else ""
        entry = entry.strip()
        if not entry or entry == "::":
            continue
        if entry.lower().startswith("::ffff:"):
            entry = entry[len("::ffff:") :]
        if _RE_IPV4.fullmatch(entry):
            out.append(entry)
        elif ":" in entry:
            try:
                ipaddress.IPv6Address(entry)
                out.append(entry)
            except ValueError:
                continue
    return list(dict.fromkeys(out))


def _flatten(event: dict) -> dict:
    """Merge an event's nested EVTX shape into one flat field dict.

    Same shape as the ``scan_dicts`` fold in ``_compute_analytics_data``
    (top-level fields, ``Details`` from Hayabusa, ``Event.EventData`` from
    Zircolite/Chainsaw) plus ``Event.System``, which analytics reads separately.
    Top-level keys win on conflict.
    """
    root = event.get("Event")
    root = root if isinstance(root, dict) else {}
    sys_d = root.get("System") if isinstance(root.get("System"), dict) else {}
    data_d = root.get("EventData") if isinstance(root.get("EventData"), dict) else {}
    details_d = event.get("Details") if isinstance(event.get("Details"), dict) else {}

    merged: dict = {}
    for d in (sys_d, data_d, details_d, event):
        for k, v in d.items():
            if k in ("Event", "Details", "EventData", "System"):
                continue
            merged[k] = v
    return merged


def _event_id(fields: dict) -> int | None:
    raw = fields.get("EventID")
    if isinstance(raw, dict):
        raw = raw.get("#text")
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _first(fields: dict, *keys: str) -> object:
    for k in keys:
        v = fields.get(k)
        if v is not None:
            return v
    return None


def extract_relationships(event: dict) -> list[tuple[str, str, str, str, str]]:
    """Extract typed relationships from a single parsed event.

    Returns a de-duplicated list of
    ``(source_value, source_type, target_value, target_type, relationship_type)``
    tuples. Values are normalized to match entity values.
    """
    if not isinstance(event, dict):
        return []
    fields = _flatten(event)
    if not fields:
        return []

    eid = _event_id(fields)
    out: list[tuple[str, str, str, str, str]] = []

    image = _norm_exe(_first(fields, "Image", "NewProcessName", "ProcessName"))
    parent = _norm_exe(_first(fields, "ParentImage", "ParentProcessName"))
    loaded = _norm_exe(fields.get("ImageLoaded"))
    comp = _norm_computer(_first(fields, *_HOSTNAME_KEYS))
    hashes = _extract_hashes(_first(fields, "Hashes", "Hash"))

    # Process tree
    if parent and image:
        out.append((parent, "executable", image, "executable", "parent_of"))
    if image and loaded:
        out.append((image, "executable", loaded, "executable", "loads"))

    # hashes_to — in Sysmon 7 (ImageLoaded) the Hashes field describes the loaded
    # image; in Sysmon 1 it describes the main Image.
    hash_owner = loaded or image
    if hash_owner and hashes:
        for h in hashes:
            out.append((hash_owner, "executable", h, "hash", "hashes_to"))

    # Host + owning user (process events expose the owner in the `User` field)
    if image and comp:
        out.append((image, "executable", comp, "computer", "runs_on"))
    owner_user = _norm_user(fields.get("User"))
    if image and owner_user:
        out.append((image, "executable", owner_user, "user", "runs_as"))

    # DNS resolution (Sysmon 22)
    qname = _norm_domain(fields.get("QueryName"))
    qresults = fields.get("QueryResults")
    if qname and isinstance(qresults, str):
        for ip in parse_sysmon_query_results(qresults):
            out.append((qname, "domain", ip, "ip_address", "resolves_to"))

    # Authentication (Security 4624/4625)
    if eid in (4624, 4625):
        tu = _norm_user(fields.get("TargetUserName"))
        src_ip = _norm_ip(fields.get("IpAddress"))
        if tu and src_ip:
            out.append((tu, "user", src_ip, "ip_address", "logs_on_from"))
        if tu and comp:
            out.append((tu, "user", comp, "computer", "logs_on_to"))

    # Network connection (Sysmon 3) — only between two external endpoints
    if eid == 3:
        src = _norm_ip(fields.get("SourceIp"))
        dst = _norm_ip(fields.get("DestinationIp"))
        if src and dst and src != dst and _looks_external(src) and _looks_external(dst):
            out.append((src, "ip_address", dst, "ip_address", "connects_to"))

    # File creation (Sysmon 11)
    if eid == 11:
        tgt = _norm_basename(fields.get("TargetFilename"))
        if image and tgt:
            out.append((image, "executable", tgt, "cmdline_file", "creates"))

    # ── Auditd / Linux (flat lowercase fields, no EventID) ─────────────────
    # A single auditd event carries pid/ppid but no parent image name, so no
    # parent_of edge is emitted here — lineage links ancestry across events.
    lx_image = _norm_exe(_first(fields, "exe", "comm", "a0"))
    if lx_image:
        lx_user = _norm_user(_first(fields, "acct", "auid", "uid"))
        if lx_user:
            out.append((lx_image, "executable", lx_user, "user", "runs_as"))
        if comp:
            out.append((lx_image, "executable", comp, "computer", "runs_on"))
        # SOCKADDR gives a single socket address — one-sided, unlike Sysmon 3.
        lx_addr = _norm_ip(fields.get("addr"))
        if lx_addr:
            out.append((lx_image, "executable", lx_addr, "ip_address", "communicates_with"))
        # PATH record: only actual file creation (nametype CREATE, or absent).
        nametype = fields.get("nametype")
        if nametype in (None, "CREATE"):
            lx_file = _norm_basename(fields.get("name"))
            if lx_file:
                out.append((lx_image, "executable", lx_file, "cmdline_file", "creates"))

    return list(dict.fromkeys(out))


def trim_evidence_event(event: dict) -> dict:
    """Project a single event down to the whitelisted ``EVIDENCE_FIELDS``.

    Flattens the event with the same ``_flatten`` shape the extractors use, then
    keeps only fields in ``EVIDENCE_FIELDS`` whose value is a non-empty scalar.
    Returns a compact dict suitable for storing as a relationship evidence sample.
    """
    if not isinstance(event, dict):
        return {}
    fields = _flatten(event)
    out: dict = {}
    for key in EVIDENCE_FIELDS:
        val = fields.get(key)
        if val is None:
            continue
        if isinstance(val, dict):
            val = val.get("#text")
        if val is None:
            continue
        if isinstance(val, (str, int, float, bool)):
            s = str(val).strip()
            if s:
                out[key] = val
    return out


# ── Persistence ────────────────────────────────────────────────────────────


def persist_relationships(
    db: Session,
    job_id: int,
    relationship_tuples: Mapping[tuple[str, str, str, str, str], int] | Iterable[tuple[str, str, str, str, str]],
    entity_map: dict[tuple[str, str], object],
    evidence: dict[tuple[str, str, str, str, str], list[dict]] | None = None,
) -> int:
    """Upsert ``EntityRelationship`` rows, resolving endpoints via ``entity_map``.

    Tuples whose source/target are not present in ``entity_map`` (or that resolve
    to the same entity) are dropped. On re-occurrence the row's ``last_seen_at`` is
    refreshed and ``occurrence_count`` is recomputed as the sum of the per-job evidence
    rows — never incremented; see the comment on the conflict clause below. Returns the
    number of distinct edges touched (inserted or updated).

    ``relationship_tuples`` is either a **mapping** of value-tuple → occurrence count, or
    a plain iterable of value-tuples (each counting once). The mapping form lets a caller
    count at the source, keeping its peak memory proportional to *distinct* edges rather
    than to ``max_parse_events`` times relationships-per-event; this function folds its
    input into that shape either way.

    When ``evidence`` is provided (keyed by the same value-tuples), an
    ``EntityRelationshipEvidence`` row is upserted per (edge, ``job_id``) carrying
    the per-job occurrence count and a capped sample of trimmed events. The per-job count
    is set wholesale, so re-running the same job (e.g. backfill) is idempotent.
    """
    from app.models import EntityRelationship

    if not relationship_tuples or not entity_map:
        return 0

    now = datetime.now(UTC)

    pairs = relationship_tuples.items() if isinstance(relationship_tuples, Mapping) else ((tup, 1) for tup in relationship_tuples)

    counts: dict[tuple[int, int, str], int] = {}
    # Resolve evidence samples (keyed by value-tuple) onto resolved id-triples.
    evidence_by_triple: dict[tuple[int, int, str], list[dict]] = {}
    for (sv, st, tv, tt, rt), occurrences in pairs:
        src = entity_map.get((sv[:500], st))
        tgt = entity_map.get((tv[:500], tt))
        if src is None or tgt is None:
            continue
        sid = src.id
        tid = tgt.id
        if sid == tid:
            continue
        key = (sid, tid, rt)
        counts[key] = counts.get(key, 0) + occurrences
        if evidence:
            samples = evidence.get((sv, st, tv, tt, rt))
            if samples and key not in evidence_by_triple:
                evidence_by_triple[key] = samples[:EVIDENCE_CAP]

    if not counts:
        return 0

    dialect = db.get_bind().dialect.name
    triples = list(counts.keys())

    for i in range(0, len(triples), _UPSERT_BATCH):
        batch = triples[i : i + _UPSERT_BATCH]
        rows = [
            {
                "source_entity_id": s,
                "target_entity_id": t,
                "relationship_type": r,
                "first_seen_at": now,
                "last_seen_at": now,
                "occurrence_count": counts[(s, t, r)],
            }
            for s, t, r in batch
        ]
        # `last_seen_at` only. The tally is NOT accumulated here: this statement runs again
        # every time a job's analytics are recomputed (the Recalculate button and
        # backfill_analytics both reach it), and `occurrence_count + excluded` would re-add
        # the job's whole contribution each time — three runs of one job taking an edge from
        # 7 to 14 to 21. It is derived from the per-job evidence rows below instead, which are
        # set wholesale per job and therefore idempotent by construction.
        conflict_update = {"last_seen_at": now}
        if dialect == "postgresql":
            stmt = pg_insert(EntityRelationship)
            stmt = stmt.values(rows).on_conflict_do_update(
                index_elements=["source_entity_id", "target_entity_id", "relationship_type"],
                set_=conflict_update,
            )
        else:
            stmt = sqlite_insert(EntityRelationship)
            stmt = stmt.values(rows).on_conflict_do_update(
                index_elements=["source_entity_id", "target_entity_id", "relationship_type"],
                set_=conflict_update,
            )
        db.execute(stmt)

    db.flush()

    _persist_relationship_evidence(db, job_id, counts, evidence_by_triple, dialect, now)

    return len(counts)


def _persist_relationship_evidence(
    db: Session,
    job_id: int,
    counts: dict[tuple[int, int, str], int],
    evidence_by_triple: dict[tuple[int, int, str], list[dict]],
    dialect: str,
    now: datetime,
) -> None:
    """Upsert one ``EntityRelationshipEvidence`` row per edge, then derive the edge tally.

    A row is written for **every** edge in *counts*, not only the ones that captured sample
    events: the row is the per-job record of how often the edge occurred, and the sample
    list (capped at ``EVIDENCE_CAP``) is extra. Without the count-only rows there is no
    complete per-job ledger, and ``EntityRelationship.occurrence_count`` cannot be derived.

    Because these rows are set wholesale per ``(relationship, job)``, summing them is
    idempotent — recomputing a job's analytics any number of times leaves the tally
    unchanged, which incrementing never could.

    On a database with jobs analysed before evidence capture, an edge has no rows for those
    jobs, so its tally is the sum of the jobs that did record one. It is a display
    count, it never becomes wrong in a new direction, and `POST /admin/backfill-relationships`
    rebuilds the full ledger from raw output for every job that still has it on disk.
    """
    from sqlalchemy import func, select, tuple_, update

    from app.json_utils import dumps as _json_dumps
    from app.models import EntityRelationship, EntityRelationshipEvidence

    triples = list(counts.keys())
    # Resolve each (source, target, rel_type) triple back to its relationship id.
    id_map: dict[tuple[int, int, str], int] = {}
    for i in range(0, len(triples), _UPSERT_BATCH):
        batch = triples[i : i + _UPSERT_BATCH]
        rows = db.execute(
            select(
                EntityRelationship.id,
                EntityRelationship.source_entity_id,
                EntityRelationship.target_entity_id,
                EntityRelationship.relationship_type,
            ).where(
                tuple_(
                    EntityRelationship.source_entity_id,
                    EntityRelationship.target_entity_id,
                    EntityRelationship.relationship_type,
                ).in_(batch)
            )
        ).all()
        for rid, sid, tid, rt in rows:
            id_map[(sid, tid, rt)] = rid

    ev_rows = [
        {
            "relationship_id": id_map[triple],
            "job_id": job_id,
            "occurrence_count": count,
            "first_seen_at": now,
            "last_seen_at": now,
            "sample_events_json": _json_dumps(evidence_by_triple.get(triple) or []),
        }
        for triple, count in counts.items()
        if triple in id_map
    ]
    if not ev_rows:
        return

    for i in range(0, len(ev_rows), _UPSERT_BATCH):
        batch = ev_rows[i : i + _UPSERT_BATCH]
        if dialect == "postgresql":
            stmt = pg_insert(EntityRelationshipEvidence)
            stmt = stmt.values(batch).on_conflict_do_update(
                index_elements=["relationship_id", "job_id"],
                set_={
                    "last_seen_at": now,
                    "occurrence_count": stmt.excluded.occurrence_count,
                    "sample_events_json": stmt.excluded.sample_events_json,
                },
            )
        else:
            stmt = sqlite_insert(EntityRelationshipEvidence)
            stmt = stmt.values(batch).on_conflict_do_update(
                index_elements=["relationship_id", "job_id"],
                set_={
                    "last_seen_at": now,
                    "occurrence_count": stmt.excluded.occurrence_count,
                    "sample_events_json": stmt.excluded.sample_events_json,
                },
            )
        db.execute(stmt)

    db.flush()

    # Derive the edge tally from the ledger we just wrote. One correlated UPDATE per batch
    # of relationship ids rather than a read-modify-write, so concurrent workers finishing
    # two jobs that share an edge cannot lose one of the contributions.
    touched = sorted(set(id_map.values()))
    for i in range(0, len(touched), _UPSERT_BATCH):
        batch_ids = touched[i : i + _UPSERT_BATCH]
        total = (
            select(func.coalesce(func.sum(EntityRelationshipEvidence.occurrence_count), 0))
            .where(EntityRelationshipEvidence.relationship_id == EntityRelationship.id)
            .scalar_subquery()
        )
        db.execute(update(EntityRelationship).where(EntityRelationship.id.in_(batch_ids)).values(occurrence_count=total))

    db.flush()
