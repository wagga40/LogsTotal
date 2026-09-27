"""Columnar wire format for the relationship graph — schema, encoder, GraphML.

Pure module: stdlib plus the other pure Intel modules. No SQLAlchemy, no FastAPI, no
session — so it is Tier-1 testable with zero DB, exactly like ``event_markers.py``, which
this format is modelled on.

**Why columnar.** One ``{"data": {…}}`` object per element, at the caps (5,000 nodes /
15,000 edges) with the threat and label columns, is roughly 3.4 MB of JSON and ~40,000
JavaScript objects to allocate before a single node is drawn. The same content as parallel
arrays with a dictionary for the one
genuinely repetitive field (tags) is ~421 KB and about fifteen arrays. Raw bytes are what
``JSON.parse`` costs and what the JS heap holds, so this is the number that matters — not
the gzipped transfer size.

**Two halves.** :func:`client_schema` is the *constant* half — palettes, enum orders, flag
bits, labels. It is rendered into the page's ``x-data`` blob so it exists before the
renderer is constructed; a palette fetched alongside the data would be ``undefined`` at
Sigma-construction time. :func:`build_payload` is the *per-request* half and carries only
indices into that schema, never a colour or a label.

**Edges reference node indices, not entity ids.** A dangling edge therefore becomes
structurally impossible rather than something the client has to defend against. The cost is
that merging a second payload (progressive expansion) is a remap and not a concatenation —
see ``mergePayload`` in ``app/static/graph-view.js``, which is unit-tested for exactly that.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple
from xml.sax.saxutils import escape as _escape
from xml.sax.saxutils import quoteattr as _quoteattr

from app.constants import ENTITY_TYPE_COLORS, GRAPH_EDGE_KIND_COLORS, SEVERITY_COLORS, SEVERITY_ORDER
from app.intel.attributes import attribute_flags, attribute_subtype
from app.intel.live_enrichment import ENRICHMENT_VERDICTS
from app.intel.queries import ATTR_FILTERS
from app.intel.relationships import RELATIONSHIP_LABELS, RELATIONSHIP_TYPES
from app.intel.tactics import MITRE_TACTICS, OTHER_TACTIC, TACTIC_COLORS, TACTIC_LABELS
from app.json_utils import loads as _json_loads

# Characters XML 1.0 cannot represent even escaped: C0 controls other than tab, LF and CR,
# lone surrogates, and U+FFFE/U+FFFF. An entity value carrying one (an ESC in a crafted task
# name) made the whole GraphML download unparseable, so they are dropped from every value.
_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml_escape(value: str) -> str:
    return _escape(_XML_ILLEGAL.sub("", value))


def _xml_attr(value: str) -> str:
    return _quoteattr(_XML_ILLEGAL.sub("", value))


GRAPH_PAYLOAD_VERSION = 1

# The two edge kinds that are *not* a typed relationship. They stay undirected: "named in
# the same log file" and "named in the same Sigma finding" are symmetric statements.
EDGE_KIND_JOB = "job"
EDGE_KIND_FINDING = "finding"

# Wire codes for `e.k`. 0 and 1 are the two undirected kinds; 2+i is `schema.rels[i]`, a
# directed typed relationship. One column expresses both, and the client derives
# directedness from `k >= EDGE_KIND_TYPED_BASE` with no second column to disagree with.
EDGE_CODE_JOB = 0
EDGE_CODE_FINDING = 1
EDGE_KIND_TYPED_BASE = 2

# Node severity/tactic/subtype columns use 0 for "none" and 1+index otherwise, so an absent
# value needs no sentinel of its own and an all-zero column costs one byte per node.
NONE_INDEX = 0

# Entity types, in the order the schema ships them. ENTITY_TYPE_COLORS is ordered to match
# the dashboard's display order, and `constants.ENTITY_TYPES` pins the same key set.
ENTITY_TYPE_ORDER: tuple[str, ...] = tuple(ENTITY_TYPE_COLORS)

# Severity enum for `n.sv`. `severity_rank_sql()` returns len(SEVERITY_ORDER) for a value it
# does not recognise, which the encoder clamps onto the trailing "unknown" slot.
SEVERITY_ORDER_WITH_UNKNOWN: tuple[str, ...] = (*SEVERITY_ORDER, "unknown")

TACTIC_ORDER: tuple[str, ...] = (*MITRE_TACTICS, OTHER_TACTIC)

# ── Flag bits ──────────────────────────────────────────────────────────────
#
# Four view flags, then one bit per *boolean* `attr:` key. Deriving the attribute bits from
# ATTR_FILTERS rather than listing them means a new boolean attribute becomes client-side
# filterable the moment it is added, with no second list to update — and the sorted() keeps
# the assignment deterministic so two processes serving the same request agree. The client
# never hardcodes a bit: it reads `schema.flags`.

_VIEW_FLAG_NAMES: tuple[str, ...] = ("watchlist", "allowlisted", "focal", "in_case")

# The boolean half of ATTR_FILTERS (`("field", True)`); the rest are categorical and become
# `subtypes` below. Together they cover ATTR_FILTERS exactly — a set-equality test in
# tests/test_intel_attributes.py enforces both directions, because a key that falls out of
# both is a `label:` filter that silently matches nothing on the graph.
ATTR_FLAG_NAMES: tuple[str, ...] = tuple(sorted(k for k, (_f, v) in ATTR_FILTERS.items() if v is True))
SUBTYPES: tuple[str, ...] = tuple(sorted(k for k, (_f, v) in ATTR_FILTERS.items() if v is not True))

NODE_FLAGS: dict[str, int] = {name: 1 << i for i, name in enumerate((*_VIEW_FLAG_NAMES, *ATTR_FLAG_NAMES))}

_SUBTYPE_INDEX = {name: i + 1 for i, name in enumerate(SUBTYPES)}
_TYPE_INDEX = {name: i for i, name in enumerate(ENTITY_TYPE_ORDER)}
_SEVERITY_INDEX = {name: i + 1 for i, name in enumerate(SEVERITY_ORDER_WITH_UNKNOWN)}
_TACTIC_INDEX = {name: i + 1 for i, name in enumerate(TACTIC_ORDER)}
_REL_INDEX = {name: i for i, name in enumerate(RELATIONSHIP_TYPES)}


class GraphNode(NamedTuple):
    """One node, as the DB builders hand it over. Deliberately not an ORM object."""

    id: int
    label: str
    entity_type: str
    job_count: int = 0
    watchlist: bool = False
    allowlisted: bool = False
    attributes_json: str | None = None


class GraphEdge(NamedTuple):
    """One edge. *kind* is ``"job"``, ``"finding"`` or a ``RELATIONSHIP_TYPES`` member.

    ``weight`` is an honest evidence count — shared jobs, shared findings, or the typed
    relationship's ``occurrence_count``. It carries no rendering constant, which would
    travel into the GraphML export as though it were data; the visibility floor lives in the
    client's stroke-width reducer.
    """

    source: int
    target: int
    kind: str
    weight: int = 1
    # `EntityRelationship.id` for a typed edge, 0 otherwise. Carried so the client can ask
    # `/intel/relationships/{id}/timespan.json` directly instead of re-resolving the row
    # from its endpoints — which would need a lookup endpoint keyed on (source, target,
    # type), i.e. a second way to address the same row and a second thing to authorize.
    rel_id: int = 0


class NodeThreat(NamedTuple):
    """Per-node threat context, all of it derived from viewer-filtered queries."""

    severity: str | None = None
    tactic: str | None = None
    verdict: int = 0


def client_schema() -> dict[str, Any]:
    """The constant half of the contract: enums, flag bits, palettes, labels.

    Rendered into the page rather than fetched, because the renderer needs the palette at
    construction time. Everything here is derived from an existing single source of truth —
    no palette is declared twice, and ``test_graph_client_declares_no_palette`` fails the
    build if a hex reappears in the client or the legend.
    """
    return {
        "v": GRAPH_PAYLOAD_VERSION,
        "flags": dict(NODE_FLAGS),
        "types": list(ENTITY_TYPE_ORDER),
        "subtypes": list(SUBTYPES),
        "attr_flags": list(ATTR_FLAG_NAMES),
        "severities": list(SEVERITY_ORDER_WITH_UNKNOWN),
        "tactics": list(TACTIC_ORDER),
        "rels": list(RELATIONSHIP_TYPES),
        "verdicts": list(ENRICHMENT_VERDICTS),
        "edge_kinds": [EDGE_KIND_JOB, EDGE_KIND_FINDING],
        "typed_base": EDGE_KIND_TYPED_BASE,
        "colors": {
            "type": dict(ENTITY_TYPE_COLORS),
            "severity": dict(SEVERITY_COLORS),
            "tactic": dict(TACTIC_COLORS),
            "kind": dict(GRAPH_EDGE_KIND_COLORS),
            "ui": {
                "focal": "#fbbf24",
                "watchlist": "#fbbf24",
                "selection": "#60a5fa",
                "muted": "#374151",
                # A *muted* label is still meant to be read — dimming says "not what you
                # asked for", not "gone". The node colour above (gray-700) is right for a
                # dimmed dot on the dark canvas but leaves text at roughly the contrast of
                # the background, so a hover overlay would effectively erase every name outside
                # the ego rather than de-emphasise them. gray-500 reads as secondary and
                # is legible; HIDDEN is what "gone" is for.
                "mutedLabel": "#6b7280",
                "label": "#e5e7eb",
                "bg": "#0b1120",
            },
        },
        "labels": {
            "types": dict(_TYPE_LABELS),
            "rels": dict(RELATIONSHIP_LABELS),
            "tactics": dict(TACTIC_LABELS),
            "kinds": {
                EDGE_KIND_JOB: "Same job (co-occurrence)",
                EDGE_KIND_FINDING: "Same Sigma finding",
                "typed": "Typed relationship",
            },
            "verdicts": {
                "clean": "Clean",
                "unknown": "Unknown",
                "suspicious": "Suspicious",
                "malicious": "Malicious",
            },
        },
    }


# Singular display labels. `constants.ENTITY_TYPE_META` is plural ("Users") because it heads
# a dashboard column; a node in a graph is one thing.
_TYPE_LABELS: dict[str, str] = {
    "user": "User",
    "computer": "Computer",
    "ip_address": "IP",
    "hash": "Hash",
    "executable": "Executable",
    "domain": "Domain",
    "cmdline_file": "Cmdline",
    "service": "Service",
    "task": "Task",
}


def _flags_for(node: GraphNode, *, focal: bool, in_case: bool) -> int:
    bits = 0
    if node.watchlist:
        bits |= NODE_FLAGS["watchlist"]
    if node.allowlisted:
        bits |= NODE_FLAGS["allowlisted"]
    if focal:
        bits |= NODE_FLAGS["focal"]
    if in_case:
        bits |= NODE_FLAGS["in_case"]
    for name in _attr_keys(node.attributes_json)[0]:
        bit = NODE_FLAGS.get(name)
        if bit:
            bits |= bit
    return bits


def _attr_keys(attributes_json: str | None) -> tuple[frozenset[str], str | None]:
    """``(boolean attr keys, categorical attr key)`` for a stored blob. Never raises."""
    if not attributes_json:
        return frozenset(), None
    try:
        attrs = _json_loads(attributes_json)
    except Exception:
        return frozenset(), None
    if not isinstance(attrs, dict):
        return frozenset(), None
    return attribute_flags(attrs), attribute_subtype(attrs)


def _severity_index(severity: object) -> int:
    """Severity name → 1+index, clamping anything unrecognised onto ``"unknown"``.

    ``models.severity_rank_sql()`` returns ``len(SEVERITY_ORDER)`` for a value it does not
    know, and callers pass that rank through; both the rank and a stray string land on the
    same trailing slot rather than silently becoming "no severity".
    """
    if severity is None:
        return NONE_INDEX
    if isinstance(severity, int) and not isinstance(severity, bool):
        if 0 <= severity < len(SEVERITY_ORDER):
            return severity + 1
        return _SEVERITY_INDEX["unknown"]
    name = str(getattr(severity, "value", severity)).lower()
    return _SEVERITY_INDEX.get(name, _SEVERITY_INDEX["unknown"])


def _edge_code(kind: str) -> int | None:
    if kind == EDGE_KIND_JOB:
        return EDGE_CODE_JOB
    if kind == EDGE_KIND_FINDING:
        return EDGE_CODE_FINDING
    rel = _REL_INDEX.get(kind)
    return None if rel is None else EDGE_KIND_TYPED_BASE + rel


def build_payload(
    *,
    scope: str,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
    stats: dict[str, Any],
    focal_id: int | None = None,
    hidden_types: list[str] | None = None,
    hidden_kinds: list[str] | None = None,
    tags: dict[int, list[str]] | None = None,
    cases: dict[int, list[int]] | None = None,
    threat: dict[int, NodeThreat] | None = None,
    matches: set[int] | None = None,
    matches_partial: bool = False,
) -> dict[str, Any]:
    """Encode nodes + edges into the columnar wire format.

    *matches*, *tags* and *cases* are keyed by **entity id**; everything on the wire comes
    back out as a node index. Edges whose endpoints are not both in *nodes* are dropped
    silently — that is the invariant node-index edges buy, and it is cheaper to enforce here
    once than to defend against on every client frame.

    Sparse columns (``tg``, ``ca``, ``mt``) are **omitted entirely** when empty rather than
    emitted as ``[]``, so ``"tg" in payload.n`` is a meaningful "were tags computed for this
    request?" probe: a request that did not compute tags is distinguishable from a graph
    whose nodes genuinely carry none.
    """
    index_of: dict[int, int] = {}
    ids: list[int] = []
    labels: list[str] = []
    types: list[int] = []
    subs: list[int] = []
    flags: list[int] = []
    jobs: list[int] = []

    case_ids = cases or {}
    for node in nodes:
        if node.id in index_of:
            continue
        index_of[node.id] = len(ids)
        _bools, sub = _attr_keys(node.attributes_json)
        ids.append(int(node.id))
        labels.append(node.label or f"entity {node.id}")
        types.append(_TYPE_INDEX.get(node.entity_type, 0))
        subs.append(_SUBTYPE_INDEX.get(sub or "", NONE_INDEX))
        flags.append(_flags_for(node, focal=(focal_id is not None and node.id == focal_id), in_case=bool(case_ids.get(node.id))))
        jobs.append(int(node.job_count or 0))

    n: dict[str, Any] = {"id": ids, "lb": labels, "ty": types, "sub": subs, "fl": flags, "jc": jobs}

    if threat:
        n["sv"] = [_severity_index(threat.get(eid, _NO_THREAT).severity) for eid in ids]
        n["tc"] = [_TACTIC_INDEX.get(threat.get(eid, _NO_THREAT).tactic or "", NONE_INDEX) for eid in ids]
        n["en"] = [int(threat.get(eid, _NO_THREAT).verdict or 0) for eid in ids]

    if tags:
        dict_tags: dict[str, int] = {}
        rows: list[list[int]] = []
        for eid, names in tags.items():
            idx = index_of.get(eid)
            if idx is None or not names:
                continue
            row = [idx]
            for name in names:
                slot = dict_tags.get(name)
                if slot is None:
                    slot = len(dict_tags)
                    dict_tags[name] = slot
                row.append(slot)
            rows.append(row)
        if rows:
            n["tg"] = rows
    else:
        dict_tags = {}

    if case_ids:
        rows = []
        for eid, cids in case_ids.items():
            idx = index_of.get(eid)
            if idx is None or not cids:
                continue
            rows.append([idx, *sorted({int(c) for c in cids})])
        if rows:
            n["ca"] = rows

    if matches:
        hits = sorted(index_of[eid] for eid in matches if eid in index_of)
        if hits:
            n["mt"] = hits
    if matches_partial:
        n["mt_partial"] = True

    src: list[int] = []
    tgt: list[int] = []
    kinds: list[int] = []
    weights: list[int] = []
    rel_ids: list[int] = []
    for edge in edges:
        code = _edge_code(edge.kind)
        if code is None:
            continue
        s = index_of.get(edge.source)
        t = index_of.get(edge.target)
        if s is None or t is None or s == t:
            continue
        src.append(s)
        tgt.append(t)
        kinds.append(code)
        weights.append(max(1, int(edge.weight or 1)))
        rel_ids.append(int(edge.rel_id or 0))

    out: dict[str, Any] = {
        "v": GRAPH_PAYLOAD_VERSION,
        "scope": scope,
        "focal": focal_id,
        "n": n,
        "e": {"s": src, "t": tgt, "k": kinds, "w": weights},
        "defaults": {"hidden_types": list(hidden_types or []), "hidden_kinds": list(hidden_kinds or [])},
        "stats": dict(stats),
    }
    if any(rel_ids):
        out["e"]["rid"] = rel_ids
    if dict_tags:
        out["dict"] = {"tags": sorted(dict_tags, key=dict_tags.__getitem__)}
    return out


_NO_THREAT = NodeThreat()


# ── GraphML ────────────────────────────────────────────────────────────────


def _decode_flags(bits: int) -> dict[str, bool]:
    return {name: bool(bits & bit) for name, bit in NODE_FLAGS.items()}


def to_graphml(payload: dict[str, Any], *, name: str = "logstotal-graph") -> str:
    """Serialise a columnar payload to GraphML for yEd / Gephi.

    Hand-rolled with proper escaping — no XML dependency, and we produce every value here,
    so there is no untrusted-input parsing surface.

    ``edgedefault`` stays ``undirected`` and typed edges carry ``directed="true"``
    per-edge. That is the spec-correct way to express a mixed graph, rather than declaring
    everything undirected and drawing an arrowhead on the typed ones.
    """
    n = payload.get("n") or {}
    e = payload.get("e") or {}
    ids: list[int] = n.get("id") or []
    labels: list[str] = n.get("lb") or []
    types: list[int] = n.get("ty") or []
    subs: list[int] = n.get("sub") or []
    flags: list[int] = n.get("fl") or []
    jobs: list[int] = n.get("jc") or []

    lines: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">'
    )
    for key, kind, typ in (
        ("label", "node", "string"),
        ("entity_type", "node", "string"),
        ("subtype", "node", "string"),
        ("watchlist", "node", "boolean"),
        ("allowlisted", "node", "boolean"),
        ("job_count", "node", "int"),
        ("focal", "node", "boolean"),
        ("kind", "edge", "string"),
        ("weight", "edge", "int"),
        ("rel_type", "edge", "string"),
    ):
        lines.append(f'  <key id="{key}" for="{kind}" attr.name="{key}" attr.type="{typ}"/>')
    lines.append(f'  <graph id={_xml_attr(name)} edgedefault="undirected">')

    for i, eid in enumerate(ids):
        decoded = _decode_flags(flags[i] if i < len(flags) else 0)
        sub_idx = subs[i] if i < len(subs) else 0
        lines.append(f'    <node id="e{int(eid)}">')
        lines.append(f'      <data key="label">{_xml_escape(str(labels[i] if i < len(labels) else ""))}</data>')
        lines.append(f'      <data key="entity_type">{_xml_escape(_type_name(types[i] if i < len(types) else 0))}</data>')
        if sub_idx:
            lines.append(f'      <data key="subtype">{_xml_escape(SUBTYPES[sub_idx - 1])}</data>')
        lines.append(f'      <data key="watchlist">{"true" if decoded["watchlist"] else "false"}</data>')
        lines.append(f'      <data key="allowlisted">{"true" if decoded["allowlisted"] else "false"}</data>')
        lines.append(f'      <data key="job_count">{int(jobs[i]) if i < len(jobs) else 0}</data>')
        lines.append(f'      <data key="focal">{"true" if decoded["focal"] else "false"}</data>')
        lines.append("    </node>")

    src: list[int] = e.get("s") or []
    tgt: list[int] = e.get("t") or []
    codes: list[int] = e.get("k") or []
    weights: list[int] = e.get("w") or []
    for i in range(len(src)):
        code = codes[i] if i < len(codes) else EDGE_CODE_JOB
        rel = RELATIONSHIP_TYPES[code - EDGE_KIND_TYPED_BASE] if code >= EDGE_KIND_TYPED_BASE else None
        kind = "typed" if rel else (EDGE_KIND_FINDING if code == EDGE_CODE_FINDING else EDGE_KIND_JOB)
        a, b = int(src[i]), int(tgt[i])
        eid = f"{rel or kind}-{a}-{b}"
        directed = ' directed="true"' if rel else ""
        lines.append(f'    <edge id="{_xml_escape(eid)}" source="e{int(ids[a])}" target="e{int(ids[b])}"{directed}>')
        lines.append(f'      <data key="kind">{kind}</data>')
        lines.append(f'      <data key="weight">{int(weights[i]) if i < len(weights) else 1}</data>')
        if rel:
            lines.append(f'      <data key="rel_type">{_xml_escape(rel)}</data>')
        lines.append("    </edge>")

    lines.append("  </graph>")
    lines.append("</graphml>")
    return "\n".join(lines)


def _type_name(idx: int) -> str:
    return ENTITY_TYPE_ORDER[idx] if 0 <= idx < len(ENTITY_TYPE_ORDER) else ""
