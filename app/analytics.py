"""Job analytics — the single event pass that produces a job's analytics blob.

Pure module: no FastAPI, no Huey. Reads an ``AnalysisJob`` (with its task results and
findings already loaded) plus the job's raw tool output, and returns a plain dict.

It lives outside ``app/routers/jobs.py`` because the *worker* is its main caller, and
importing a router would drag the whole web tier — FastAPI, Jinja, every router-level
import — into the Huey process. The router owns presentation (``_hydrate_analytics`` adds
colours for templates); this module owns the computation, as ``app/intel/event_timeline.py``
does for timelines.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Collection
from pathlib import Path
from typing import TYPE_CHECKING

from app.constants import RE_DOMAIN, RE_HASH, RE_IPV4, RE_IPV6
from app.intel.event_markers import MarkerAccumulator, build_index
from app.intel.event_timeline import extract_all_from_raw_output, format_timeline
from app.intel.tactics import _MITRE_TACTICS, _build_findings_index

if TYPE_CHECKING:
    from app.models import AnalysisJob

# Shared observable patterns, compiled once in app.constants.
_RE_IPV4 = RE_IPV4
_RE_IPV6 = RE_IPV6
_RE_HASH = RE_HASH
_RE_DOMAIN = RE_DOMAIN

# Quotes and '=' delimit a filename inside a larger shell/PowerShell/WMI token but never
# occur in one. Stripping them only at the *ends* of a whitespace token leaves the syntax
# glued to the basename, which is how job 17 produced `"powershell.exe` (an escaped \" in a
# nested `-C "..."`), `$commandline="cmd.exe` (a ScriptBlockText assignment — no quote at
# either end, so the strip was a no-op) and `name='sandcat.exe` (a WMI -Filter string).
#
# The optional leading backslash matters: it is an *escape*, not a path separator, so it has
# to be consumed with the quote it escapes. Otherwise `replace("\\", "/")` turns it into one
# and os.path.basename either keeps it as a prefix (`\"foo.exe` -> `"foo.exe`) or, on a
# trailing `\"`, drops the name entirely (`foo.exe\` -> `foo.exe/` -> "").
_RE_CMDLINE_DELIM = re.compile(r"""(?:\\?["'=])+""")


def extract_cmdline_basenames(value: str, exts: Collection[str]) -> set[str]:
    """Basenames of files referenced by a command line, restricted to ``exts``.

    Pure and self-contained so the tokenizer can be tested directly (Tier 1).
    """
    found: set[str] = set()
    for raw in value.split():
        # A token that is itself a `--flag=value` option is not a file.
        if raw.strip("'\"").startswith("-") and "=" in raw:
            continue
        for frag in _RE_CMDLINE_DELIM.split(raw):
            base = os.path.basename(frag.replace("\\", "/")).lower()
            if len(base) > 1 and os.path.splitext(base)[1] in exts:
                found.add(base)
    return found


def _compute_analytics_data(job: AnalysisJob, job_dir: Path | None = None) -> dict:  # noqa: C901 — known debt: the single event pass
    """Compute raw analytics dict (no color/rgb). Safe to call from sync worker.

    ``job_dir`` is where the raw output is, when that is not this machine's
    ``upload_dir`` — the S3 backend's copy, from ``storage.job_outputs_dir``. The inline
    pass leaves it None: it runs before the outputs are synced away.

    The returned dict carries a transient ``"relationships"`` key (typed entity
    edges extracted in the same event pass). It is consumed by
    ``persist_entities_from_analytics`` and stripped before storage via
    ``analytics_json_payload`` — it is never persisted to ``analytics_json``.
    """
    from app.analytics_fields import get_analytics_fields
    from app.intel.relationships import EVIDENCE_CAP, extract_relationships, trim_evidence_event
    from app.threat_detection import ThreatAccumulator

    cfg = get_analytics_fields()

    # Single pass: rule-tactic map, technique-tactic map, MITRE tactic counts, and the
    # rule -> (id, severity, finding_id) map the events-timeline markers need.
    rule_meta: dict[str, tuple[str | None, str | None, int | None]] = {}
    rule_tactic, technique_tactic, tactic_counts = _build_findings_index(job, rule_meta=rule_meta)

    # The zoomable events timeline rides the parse the histogram already does — one read of
    # the raw output produces both. Transient like "relationships": consumed by the worker
    # (which gzips it onto AnalysisJob.event_markers) and stripped before analytics_json.
    markers = MarkerAccumulator()

    # Build dispatch dict: field_name -> list of extraction type tags, so each field costs
    # a single dict-key lookup instead of one inner loop per extraction type.
    _FIELD_DISPATCH: dict[str, list[str]] = {}
    for k in cfg.user_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("user")
    for k in cfg.ip_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("ip")
    for k in cfg.hash_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("hash")
    for k in cfg.image_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("image")
    for k in cfg.domain_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("domain")
    for k in cfg.cmdline_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("cmdline")
    for k in cfg.service_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("service")
    for k in cfg.task_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("task")
    for k in cfg.hostname_keys:
        _FIELD_DISPATCH.setdefault(k, []).append("computer")

    _noise = cfg.noise_users
    _cmdline_exts = cfg.cmdline_exts
    _JUNK_BASENAMES = frozenset(("-", "?", ".", ".."))
    # Placeholder hosts from offline-mode tools (Zircolite host="offline") — not real machines.
    _HOST_NOISE = frozenset(("offline", "-", "n/a", "unknown"))

    users: set[str] = set()
    computers: set[str] = set()
    ip_addresses: set[str] = set()
    hashes: set[str] = set()
    executables: set[str] = set()
    domains: set[str] = set()
    cmdline_files: set[str] = set()
    services: set[str] = set()
    tasks: set[str] = set()
    threat = ThreatAccumulator()
    # A Counter, not a list: one entry per relationship *per event* would grow with
    # `max_parse_events` (250,000) times relationships-per-event, and
    # `persist_relationships` folds its input into exactly this shape anyway. Peak is
    # proportional to the number of distinct edges.
    relationship_pairs: Counter[tuple[str, str, str, str, str]] = Counter()
    relationship_evidence: dict[tuple[str, str, str, str, str], list[dict]] = {}

    # Streamed, not materialised. Holding every matched event *and* a second list of each
    # event's scan dicts would, at MAX_PARSE_EVENTS, set the worker's memory ceiling and
    # therefore its concurrency. Everything below is a fold: entity sets, relationship
    # pairs, capped evidence, and the threat accumulator.
    def _consume(event: dict) -> None:  # noqa: C901 — known debt: the field-dispatch chain
        if not isinstance(event, dict):
            return

        rels = extract_relationships(event)
        if rels:
            relationship_pairs.update(rels)
            trimmed: dict | None = None
            for tup in rels:
                bucket = relationship_evidence.setdefault(tup, [])
                if len(bucket) >= EVIDENCE_CAP:
                    continue
                if trimmed is None:
                    trimmed = trim_evidence_event(event)
                if trimmed:
                    bucket.append(trimmed)

        evtx_root = event.get("Event", {})
        evtx_data = evtx_root.get("EventData", {}) if isinstance(evtx_root, dict) else {}
        evtx_sys = evtx_root.get("System", {}) if isinstance(evtx_root, dict) else {}

        comp = event.get("Computer") or (evtx_sys.get("Computer") if isinstance(evtx_sys, dict) else None)
        if comp and isinstance(comp, str):
            computers.add(comp.strip())

        detail_dict = event.get("Details", {})

        scan_dicts = [event]
        if isinstance(detail_dict, dict):
            scan_dicts.append(detail_dict)
        if isinstance(evtx_data, dict) and evtx_data:
            scan_dicts.append(evtx_data)

        threat.add(scan_dicts)

        for d in scan_dicts:
            for key, val in d.items():
                extractors = _FIELD_DISPATCH.get(key)
                if extractors is None:
                    continue
                for ext_type in extractors:
                    if ext_type == "user":
                        if isinstance(val, str):
                            v = val.strip()
                            if v and v.lower() not in _noise and not v.endswith("$"):
                                users.add(v)
                    elif ext_type == "ip":
                        if isinstance(val, str):
                            ip_addresses.update(_RE_IPV4.findall(val))
                            ip_addresses.update(_RE_IPV6.findall(val))
                    elif ext_type == "hash":
                        if isinstance(val, str):
                            if "=" in val:
                                for part in val.split(","):
                                    part = part.strip()
                                    if "=" in part:
                                        _, hv = part.split("=", 1)
                                        hv = hv.strip()
                                        if _RE_HASH.fullmatch(hv):
                                            hashes.add(hv.upper())
                            elif _RE_HASH.fullmatch(val.strip()):
                                hashes.add(val.strip().upper())
                    elif ext_type == "image":
                        if isinstance(val, str) and val.strip():
                            name = os.path.basename(val.replace("\\", "/")).strip().lower()
                            if name and len(name) > 1 and name not in _JUNK_BASENAMES:
                                executables.add(name)
                    elif ext_type == "domain":
                        if isinstance(val, str) and val.strip() and "." in val:
                            v = val.strip().lower()
                            if _RE_IPV4.fullmatch(v):
                                ip_addresses.add(v)
                            elif ":" in v:
                                ip_addresses.update(_RE_IPV6.findall(v))
                            elif _RE_DOMAIN.fullmatch(v):
                                domains.add(v)
                    elif ext_type == "cmdline":
                        if isinstance(val, str):
                            cmdline_files.update(b for b in extract_cmdline_basenames(val, _cmdline_exts) if b not in executables)
                    elif ext_type == "service":
                        if val is not None:
                            sval = str(val).strip()
                            if sval:
                                services.add(sval)
                    elif ext_type == "task":
                        if isinstance(val, str) and val.strip():
                            tasks.add(val.strip())
                    elif ext_type == "computer":
                        if isinstance(val, str) and val.strip() and val.strip().lower() not in _HOST_NOISE:
                            computers.add(val.strip())

    full_buckets, _ = extract_all_from_raw_output(
        job.id,
        rule_tactic,
        technique_tactic,
        markers=markers,
        rule_meta=rule_meta,
        consumer=_consume,
        job_dir=job_dir,
    )
    timeline, timeline_tactics = format_timeline(full_buckets)

    threat_data = threat.result()

    return {
        "mitre_tactics": {t: tactic_counts[t] for t in _MITRE_TACTICS},
        "timeline": timeline,
        "timeline_tactics": timeline_tactics,
        "users": sorted(users),
        "computers": sorted(computers),
        "ip_addresses": sorted(ip_addresses),
        "hashes": sorted(hashes),
        "executables": sorted(executables),
        "domains": sorted(domains),
        "cmdline_files": sorted(cmdline_files - executables),
        "services": sorted(services),
        "tasks": sorted(tasks),
        "threat_detection": threat_data,
        "relationships": relationship_pairs,
        "relationship_evidence": relationship_evidence,
        "event_markers": build_index(markers),
    }


# Transient analytics keys computed for downstream persistence but never stored
# in AnalysisJob.analytics_json (they would only bloat the cached blob).
_TRANSIENT_ANALYTICS_KEYS = ("relationships", "relationship_evidence", "event_markers")


def analytics_json_payload(data: dict) -> dict:
    """Return the analytics dict minus transient keys, ready for JSON storage."""
    if any(k in data for k in _TRANSIENT_ANALYTICS_KEYS):
        return {k: v for k, v in data.items() if k not in _TRANSIENT_ANALYTICS_KEYS}
    return data
