"""MITRE ATT&CK tactic resolution — shared by job-detail analytics and the Intel threats card.

Pure Python: no FastAPI, no Huey, no DB imports. `_build_findings_index` accepts a SQLAlchemy
AnalysisJob but only touches its attribute graph — it is safe to call from a route or a worker.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import AnalysisJob


_MITRE_TACTICS = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

_MITRE_TACTICS_SET = frozenset(_MITRE_TACTICS)

# ATT&CK rainbow — one distinct hue per tactic, violet→red→orange→yellow→green→teal→blue→purple→pink→red
_MITRE_TACTIC_COLORS = {
    "reconnaissance": "#b04bff",
    "resource_development": "#7c3aed",
    "initial_access": "#e11d48",
    "execution": "#f97316",
    "persistence": "#eab308",
    "privilege_escalation": "#84cc16",
    "defense_evasion": "#22c55e",
    "credential_access": "#14b8a6",
    "discovery": "#38bdf8",
    "lateral_movement": "#3b82f6",
    "collection": "#6366f1",
    "command_and_control": "#a855f7",
    "exfiltration": "#ec4899",
    "impact": "#ef4444",
}

_OTHER_TACTIC = "_other"
_OTHER_TACTIC_COLOR = "#4b5563"  # gray-600

# Public aliases. The relationship graph ships tactic names and hexes to a WebGL canvas
# that cannot use a Tailwind class, so it needs the palette itself — the same reason
# `constants.SEVERITY_COLORS` exists. Re-exported rather than duplicated.
MITRE_TACTICS: tuple[str, ...] = tuple(_MITRE_TACTICS)
OTHER_TACTIC = _OTHER_TACTIC
TACTIC_COLORS: dict[str, str] = {**_MITRE_TACTIC_COLORS, _OTHER_TACTIC: _OTHER_TACTIC_COLOR}

# Hayabusa abbreviations → canonical tactic name
_HAYABUSA_TACTIC_ABBREV = {
    "recon": "reconnaissance",
    "resdev": "resource_development",
    "initaccess": "initial_access",
    "exec": "execution",
    "persis": "persistence",
    "privesc": "privilege_escalation",
    "evas": "defense_evasion",
    "credaccess": "credential_access",
    "disc": "discovery",
    "latmov": "lateral_movement",
    "collect": "collection",
    "c2": "command_and_control",
    "exfil": "exfiltration",
    "impact": "impact",
}

_RE_TECHNIQUE_ID = re.compile(r"[tT]\d{4}")


# Title-case display labels — the case-timeline chips and the graph client schema.
TACTIC_LABELS: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    _OTHER_TACTIC: "Other",
}


def _hex_to_rgb(h: str) -> str:
    h = h.lstrip("#")
    return f"{int(h[0:2], 16)},{int(h[2:4], 16)},{int(h[4:6], 16)}"


def normalize_tactic_tag(tag: object) -> str | None:
    """One Sigma tag → a canonical tactic name, or None if it isn't one.

    ``attack.defense-evasion``, ``defense_evasion`` and ``Defense Evasion`` are the same
    tactic; ``attack.t1055`` is a technique and yields None.
    """
    key = str(tag or "").lower()
    if key.startswith("attack."):
        key = key[len("attack.") :]
    key = key.replace("-", "_").replace(" ", "_")
    return key if key in _MITRE_TACTICS_SET else None


def primary_tactic_from_tags(tags: object) -> str | None:
    """The dominant tactic in a Sigma tag list, in kill-chain order, or None.

    Shared with ``_build_findings_index`` so the graph's per-node tactic and the job
    analytics' per-rule tactic cannot drift: "earliest tactic in ``_MITRE_TACTICS`` order
    wins" is one rule with one implementation. Accepts a list, a CSV string, or junk.
    """
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    if not isinstance(tags, list):
        return None
    found = {t for t in (normalize_tactic_tag(tag) for tag in tags) if t}
    if not found:
        return None
    return next(t for t in _MITRE_TACTICS if t in found)


def _build_findings_index(
    job: AnalysisJob,
    *,
    rule_meta: dict[str, tuple[str | None, str | None, int | None]] | None = None,
) -> tuple[dict[str, str], dict[str, str], dict[str, int]]:
    """Single-pass extraction of rule-tactic map, technique-tactic map,
    and MITRE tactic counts from DB findings.

    Returns ``(rule_tactic, technique_tactic, tactic_counts)``.

    ``rule_meta`` is an optional out-param: pass a dict and it is filled with
    ``rule_name -> (rule_id, severity, finding_id)`` from the same walk, for the
    events-timeline marker index. An out-param rather than a fourth return value because
    every caller unpacks the arity; the point is to avoid a *second* pass over every
    finding, not to restructure them.
    """
    from app.json_utils import loads as json_loads  # local import to avoid top-level cycle

    rule_tactic: dict[str, str] = {}
    technique_tactic: dict[str, str] = {}
    tactic_counts: dict[str, int] = dict.fromkeys(_MITRE_TACTICS, 0)

    for tr in job.task_results:
        for f in tr.findings:
            if rule_meta is not None and f.rule_name not in rule_meta:
                # ``Finding.severity`` is an Enum(Severity); unwrap to the plain string so
                # the marker index stores "high" and not "Severity.HIGH" (a str-subclass
                # enum still formats as the latter under str() on 3.11+). getattr rather
                # than an import keeps this module free of app.models.
                #
                # ``f.id`` rides along so an events-timeline marker can deep-link into the
                # existing /jobs/findings/{id}/rule and /events partials — the only way the
                # panel can show the Sigma rule and real sample events without a second
                # index. First finding wins per rule name, which is what the marker key
                # (rule + computer + tool) already assumes.
                rule_meta[f.rule_name] = (f.rule_id, getattr(f.severity, "value", f.severity), f.id)
            tags = json_loads(f.tags or "[]")
            if not isinstance(tags, list):
                continue
            tactics: list[str] = []
            techniques: list[str] = []

            for tag in tags:
                key = normalize_tactic_tag(tag)
                if key is not None:
                    tactics.append(key)
                    tactic_counts[key] = tactic_counts.get(key, 0) + f.count
                else:
                    m = _RE_TECHNIQUE_ID.match(str(tag).lower().removeprefix("attack."))
                    if m:
                        techniques.append(m.group().lower())

            if tactics:
                primary = next(
                    (t for t in _MITRE_TACTICS if t in tactics),
                    tactics[0],
                )
                if f.rule_name not in rule_tactic:
                    rule_tactic[f.rule_name] = primary
                for tech in techniques:
                    technique_tactic.setdefault(tech, primary)

    return rule_tactic, technique_tactic, tactic_counts


def _resolve_tactic_from_event(
    event: dict,
    rule_tactic: dict[str, str],
    technique_tactic: dict[str, str],
    rule_name: str,
) -> str:
    """Resolve MITRE tactic for a raw event using multiple strategies.

    1. Rule name → DB rule_tactic map (fast, most common)
    2. Hayabusa ``MitreTactics`` field (abbreviation lookup)
    3. Technique IDs from ``MitreTags`` / ``OtherTags`` → learned mapping
    """
    # Strategy 1: rule name
    tactic = rule_tactic.get(rule_name)
    if tactic:
        return tactic

    # Strategy 2: Hayabusa MitreTactics field (abbreviations like "Evas")
    mt = event.get("MitreTactics")
    if mt:
        vals = mt if isinstance(mt, list) else [t.strip() for t in str(mt).split(",")]
        for v in vals:
            mapped = _HAYABUSA_TACTIC_ABBREV.get(v.lower())
            if mapped:
                return mapped

    # Strategy 3: technique IDs in MitreTags / OtherTags → learned mapping
    for field in ("MitreTags", "OtherTags", "tags"):
        raw = event.get(field)
        if not raw:
            continue
        items = raw if isinstance(raw, list) else [t.strip() for t in str(raw).split(",")]
        for item in items:
            m = _RE_TECHNIQUE_ID.match(str(item).lower())
            if m:
                resolved = technique_tactic.get(m.group())
                if resolved:
                    return resolved

    return _OTHER_TACTIC


# ── ATT&CK Navigator layer ─────────────────────────────────────────────────


#: Navigator layer envelope constants. Pinned here rather than at each call site because a
#: layer whose `versions` block does not match the Navigator that opens it fails to import
#: with no useful message.
NAVIGATOR_VERSIONS = {"navigator": "5.0", "layer": "4.5", "attack": "16"}
NAVIGATOR_GRADIENT = ["#cef2ce", "#fcf199", "#f7b68a", "#f28b82"]


def build_navigator_layer(*, name: str, description: str, counts: dict[str, int], comment: Callable[[str, int], str] | None = None) -> dict:
    """A MITRE ATT&CK Navigator layer JSON from `{technique_id: count}`.

    Pure — no DB, no request. Shared by the two exports that produce a layer
    (`/intel/mitre-layer` over the viewer's jobs, and the per-entity one), so their versions
    and gradient match by construction.

    `comment` renders the per-technique hover text; the default is the count alone.
    """
    max_score = max(counts.values()) if counts else 1
    render = comment or (lambda _tid, cnt: f"{cnt} event{'s' if cnt != 1 else ''}")
    return {
        "name": name,
        "versions": dict(NAVIGATOR_VERSIONS),
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 3,
        "gradient": {"colors": list(NAVIGATOR_GRADIENT), "minValue": 0, "maxValue": max_score},
        "techniques": [
            {
                "techniqueID": tid,
                "score": cnt,
                "comment": render(tid, cnt),
                "color": "",
                "enabled": True,
            }
            for tid, cnt in sorted(counts.items())
        ],
    }
