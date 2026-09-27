"""Raw-output timeline extraction — shared by job analytics and the case attack-timeline
endpoint.

Pure Python: no FastAPI, no Huey, no SQLAlchemy
models — only stdlib, ``app.config.settings`` (for ``upload_dir``), ``app.json_utils``,
``app.intel.tactics`` and ``app.intel.event_markers``.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from app.config import settings
from app.intel.event_markers import (
    _RE_AUDIT_EPOCH,
    _RE_ISO_HOUR_PREFIX,
    MarkerAccumulator,
    normalize_severity,
)
from app.intel.tactics import (
    _MITRE_TACTIC_COLORS,
    _MITRE_TACTICS,
    _OTHER_TACTIC,
    _OTHER_TACTIC_COLOR,
    _resolve_tactic_from_event,
)
from app.json_utils import load_file as json_load_file
from app.json_utils import loads as json_loads

_log = logging.getLogger(__name__)

# Upper bound on events read from a job's raw tool output in one pass. Bounds CPU for the
# (anonymous-reachable) process-tree + analytics paths when a job produced a pathologically
# large number of matched events, and memory for the process tree, which still materialises.
# Operator-tunable via MAX_PARSE_EVENTS; read once at import, like every other module-level
# constant derived from settings.
MAX_PARSE_EVENTS = settings.max_parse_events

# Raw tool-output filename suffixes → the tool that wrote them. Single source of truth
# shared by ``extract_all_from_raw_output`` (materialises the list), ``has_raw_output``
# (short-circuits on the first match) and the marker sink (labels each marker's origin).
# Keep these in lock-step: the case-timeline coverage notice trusts the first two to agree
# on what counts as raw output.
_TOOL_BY_SUFFIX = {
    "_hayabusa.json": "hayabusa",
    "_chainsaw.json": "chainsaw",
    "_zircolite.json": "zircolite",
    "_chopchopgo.json": "chopchopgo",
}
_OUTPUT_SUFFIXES = tuple(_TOOL_BY_SUFFIX)


def _local_job_dir(job_id: int) -> Path:
    """Where a job's raw output sits *on this machine*.

    The default for both readers, and correct only on the local-disk backend. On S3 the
    worker uploads the tree and removes its local copy, and in a multi-server layout the
    worker is not even the same machine as the web tier — so this path does not exist and
    both readers return "no raw output", which every surface renders as its own empty
    state rather than an error — a process tree blank on a deployment while working locally.

    This module stays filesystem-only on purpose (importing `app.storage` would drag boto3
    into the pure parsing layer), so the resolution belongs to the impure caller:
    `intel/process_tree.py` and `routers/cases.py` open `storage.job_outputs_dir()` and
    pass the directory it yields in as `job_dir=`.
    """
    return Path(settings.upload_dir) / f"job_{job_id}"


def _iter_output_files(job_dir: Path) -> Iterator[Path]:
    """Yield the raw tool-output files under *job_dir* (recursive, suffix-matched)."""
    for f in job_dir.rglob("*"):
        if f.is_file() and f.name.lower().endswith(_OUTPUT_SUFFIXES):
            yield f


def extract_timestamp(event: dict) -> str | None:
    """Extract a timestamp string from a single event dict (any tool format)."""
    ts = event.get("Timestamp") or event.get("timestamp")
    if ts and isinstance(ts, str) and len(ts) >= 13:
        return ts

    evtx_root = event.get("Event")
    if isinstance(evtx_root, dict):
        evtx_sys = evtx_root.get("System")
        if isinstance(evtx_sys, dict):
            tc = evtx_sys.get("TimeCreated_attributes")
            if isinstance(tc, dict):
                st = tc.get("SystemTime")
                if isinstance(st, str) and len(st) >= 13:
                    return st

    return None


def parse_single_output_file(  # noqa: C901 — known debt: one branch per tool output shape
    output_file: Path,
    rt: dict[str, str],
    tt: dict[str, str],
    *,
    markers: MarkerAccumulator | None = None,
    rule_meta: dict[str, tuple[str | None, str | None, int | None]] | None = None,
    consumer: Callable[[dict], None] | None = None,
    max_events: int | None = None,
) -> tuple[dict[str, dict[str, int]], list[dict]]:
    """Parse one tool output file into (buckets, events). Thread-safe.

    ``consumer`` streams: each event is handed to it and **not** retained, so the returned
    event list is empty — on a large job that list would be the biggest allocation the
    worker makes. Callers that need the events (the process tree) pass no consumer and get
    the list.

    ``markers`` is an optional sink for the zoomable events timeline, filled alongside the
    hourly buckets so no second parse is ever needed. It has to be filled *here* rather
    than downstream because this is the only place rule identity is still in scope: a
    Zircolite output file is a list of *rules*, each with a ``matches`` list whose event
    dicts carry no rule title at all, so by the time events reach the analytics loop the
    rule they matched is gone.

    ``rule_meta`` maps ``rule_name -> (rule_id, severity, finding_id)`` and comes from
    ``tactics._build_findings_index``, which already walks the job's findings. It is the
    canonical source for both fields: severity is not uniformly present on raw events —
    ChopChopGo emits only ``Title``, and its adapter recovers the level from the Sigma YAML
    after the fact — and only the DB has a stable ``rule_id`` for tools that emit a title.
    ``finding_id`` lets a marker deep-link to the existing per-finding rule/events partials.
    """
    buckets: dict[str, dict[str, int]] = {}
    events: list[dict] = []
    # Counted separately from `events` because in consumer mode nothing is retained, so
    # `len(events)` would never reach the cap and the parse would be unbounded.
    seen = 0
    max_events = MAX_PARSE_EVENTS if max_events is None else max_events
    meta = rule_meta or {}
    tool = _TOOL_BY_SUFFIX.get(next((s for s in _OUTPUT_SUFFIXES if output_file.name.lower().endswith(s)), ""), "")

    def _mark(ts: str | None, tactic: str, rule_name: str, event: dict, level: object = None):
        if markers is None:
            return
        # Indexed rather than unpacked. The parse below is wrapped in a non-fatal `except
        # Exception`, so a rule_meta tuple of the wrong width would not fail the job — it
        # would abort every file's parse and leave every job with an empty index, visible
        # only as a log warning.
        entry = meta.get(rule_name) or ()
        rule_id = entry[0] if len(entry) > 0 else None
        severity = entry[1] if len(entry) > 1 else None
        finding_id = entry[2] if len(entry) > 2 else None
        markers.add(
            (rule_id, rule_name, severity or normalize_severity(level), tactic, _event_computer(event), tool, finding_id),
            ts,
        )

    def _record(ts: str | None, tactic: str):
        # Normalize before slicing the hour. Tools disagree on the date/time separator —
        # Hayabusa emits "2021-12-01 09:23:45 +09:00", Chainsaw "2021-12-01T09:23:45" —
        # so the raw ``ts[:13]`` would give the same hour two keys and never merge the two
        # tools' events into one bar, and since ' ' < 'T' a mixed job would sort every
        # Hayabusa hour ahead of every Chainsaw one. This also folds auditd's
        # ``audit(<epoch>.<frac>:<serial>)`` form into the same axis.
        normalized = normalize_event_time(ts)
        if not normalized:
            return
        hour = normalized[:13]
        bkt = buckets.get(hour)
        if bkt is None:
            bkt = {}
            buckets[hour] = bkt
        bkt[tactic] = bkt.get(tactic, 0) + 1

    name = output_file.name.lower()
    try:
        if name.endswith("_hayabusa.json"):
            with open(output_file, "rb") as fh:
                for line in fh:
                    if seen >= max_events:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json_loads(line)
                    except (ValueError, KeyError):
                        continue
                    rname = event.get("RuleTitle", "")
                    tactic = _resolve_tactic_from_event(event, rt, tt, rname)
                    ts = extract_timestamp(event)
                    _record(ts, tactic)
                    _mark(ts, tactic, rname, event, event.get("Level"))
                    seen += 1
                    if consumer is None:
                        events.append(event)
                    else:
                        consumer(event)

        elif name.endswith("_chainsaw.json"):
            with open(output_file, "rb") as fh:
                for line in fh:
                    if seen >= max_events:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json_loads(line)
                    except (ValueError, KeyError):
                        continue
                    rname = event.get("name", event.get("group", ""))
                    tactic = _resolve_tactic_from_event(event, rt, tt, rname)
                    ts = extract_timestamp(event)
                    _record(ts, tactic)
                    _mark(ts, tactic, rname, event, event.get("level"))
                    seen += 1
                    if consumer is None:
                        events.append(event)
                    else:
                        consumer(event)

        elif name.endswith("_chopchopgo.json"):
            data = json_load_file(output_file)
            if isinstance(data, list):
                for event in data:
                    if seen >= max_events:
                        break
                    if not isinstance(event, dict):
                        continue
                    rname = event.get("Title", "")
                    tactic = _resolve_tactic_from_event(event, rt, tt, rname)
                    ts = extract_timestamp(event)
                    _record(ts, tactic)
                    # ChopChopGo events carry no level of their own — rule_meta is the only source.
                    _mark(ts, tactic, rname, event)
                    seen += 1
                    if consumer is None:
                        events.append(event)
                    else:
                        consumer(event)

        elif name.endswith("_zircolite.json"):
            data = json_load_file(output_file)
            if isinstance(data, list):
                for rule in data:
                    if seen >= max_events:
                        break
                    rname = rule.get("title", "")
                    tactic = rt.get(rname, _OTHER_TACTIC)
                    # The rule's own level, one level up from the matches that lose it.
                    level = rule.get("level")
                    for match in rule.get("matches", []):
                        if seen >= max_events:
                            break
                        if isinstance(match, dict):
                            ts = extract_timestamp(match)
                            _record(ts, tactic)
                            _mark(ts, tactic, rname, match, level)
                            seen += 1
                            if consumer is None:
                                events.append(match)
                            else:
                                consumer(match)
    except Exception:
        # Deliberately non-fatal: analytics and the timelines are best-effort views over
        # raw tool output, and a truncated or half-written file must not fail the job whose
        # findings are already committed. But not silent: a systematically unparseable
        # output shape would otherwise look identical to a job that genuinely had no events —
        # an empty timeline with no way to tell which. Whatever was parsed before the
        # failure is still returned.
        _log.warning("timeline parse aborted for %s after %d event(s)", output_file, seen, exc_info=True)

    return buckets, events


def merge_buckets(bucket_dicts: Iterable[dict]) -> dict[str, dict[str, int]]:
    """Merge multiple ``{hour: {tactic: count}}`` dicts into one, summing overlapping counts.

    Does not mutate any input dict. Order of iteration doesn't matter — summation is
    commutative and each input's own hour/tactic dicts are only ever read, never written.
    """
    merged: dict[str, dict[str, int]] = {}
    for bucket_dict in bucket_dicts:
        for hour, tactic_counts in bucket_dict.items():
            mbkt = merged.get(hour)
            if mbkt is None:
                merged[hour] = dict(tactic_counts)
            else:
                for tactic, count in tactic_counts.items():
                    mbkt[tactic] = mbkt.get(tactic, 0) + count
    return merged


def extract_all_from_raw_output(
    job_id: int,
    rule_tactic: dict[str, str] | None = None,
    technique_tactic: dict[str, str] | None = None,
    *,
    markers: MarkerAccumulator | None = None,
    rule_meta: dict[str, tuple[str | None, str | None, int | None]] | None = None,
    consumer: Callable[[dict], None] | None = None,
    job_dir: Path | None = None,
) -> tuple[dict[str, dict[str, int]], list[dict]]:
    """Read raw tool output files and extract ALL events.

    Uses thread-parallel I/O when multiple output files exist.

    Returns ``(timeline_buckets, all_events)`` where:
    - timeline_buckets: ``{iso_hour_key: {tactic: count}}`` for timeline
    - all_events: every parsed event dict for entity/threat extraction

    ``consumer`` streams instead: each event is handed to it and the returned list is
    empty, keeping the analytics pass off a 250,000-dict peak that would otherwise set the
    worker's memory ceiling. The consumer is called under a lock so it may be
    stateful — the parse still parallelises across files, and the consumer's own work is
    CPU-bound Python that the GIL serialises anyway.

    ``markers``/``rule_meta`` are the optional events-timeline sink documented on
    :func:`parse_single_output_file`. Each worker thread fills a private accumulator that
    is folded into the caller's under the ``as_completed`` loop — the same discipline
    ``file_bucket_list`` already uses, and the reason ``MarkerAccumulator`` needs no lock.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    job_dir = job_dir or _local_job_dir(job_id)
    if not job_dir.is_dir():
        return {}, []

    rt = rule_tactic or {}
    tt = technique_tactic or {}

    output_files = list(_iter_output_files(job_dir))

    if not output_files:
        return {}, []

    if len(output_files) == 1:
        return parse_single_output_file(output_files[0], rt, tt, markers=markers, rule_meta=rule_meta, consumer=consumer)

    all_events: list[dict] = []
    file_bucket_list: list[dict[str, dict[str, int]]] = []

    # The cap is a job-wide budget, not a per-file one: without this each of four files
    # could stream MAX_PARSE_EVENTS and the total would be 4x the documented limit. In the
    # materialising path the same job-wide truncation happens after the join.
    remaining = MAX_PARSE_EVENTS
    guarded: Callable[[dict], None] | None = None
    if consumer is not None:
        lock = threading.Lock()

        def guarded(event: dict, _consumer=consumer) -> None:
            nonlocal remaining
            with lock:
                if remaining <= 0:
                    return
                remaining -= 1
                _consumer(event)

    def _parse(path: Path):
        sink = MarkerAccumulator() if markers is not None else None
        return (*parse_single_output_file(path, rt, tt, markers=sink, rule_meta=rule_meta, consumer=guarded), sink)

    with ThreadPoolExecutor(max_workers=min(len(output_files), 4)) as pool:
        futures = {pool.submit(_parse, f): f for f in output_files}
        for fut in as_completed(futures):
            try:
                file_buckets, file_events, file_markers = fut.result()
            except Exception:
                continue
            all_events.extend(file_events)
            file_bucket_list.append(file_buckets)
            if markers is not None and file_markers is not None:
                markers.merge(file_markers)

    merged_buckets = merge_buckets(file_bucket_list)

    if len(all_events) > MAX_PARSE_EVENTS:
        all_events = all_events[:MAX_PARSE_EVENTS]
    return merged_buckets, all_events


def format_timeline(
    timeline_raw: dict[str, dict[str, int]],
) -> tuple[list[dict], list[dict]]:
    """Turn ``{hour_key: {tactic: count}}`` into template-ready timeline + legend.

    Returns ``(timeline_items, timeline_tactics)`` where each item has a
    ``segments`` list ordered bottom-to-top for stacked rendering.
    """
    from datetime import datetime as _dt

    if not timeline_raw:
        return [], []

    keys = sorted(timeline_raw.keys())
    multi_year = keys[0][:4] != keys[-1][:4]
    multi_day = keys[0][:10] != keys[-1][:10]
    fmt = "%Y %b %d %H:%M" if multi_year else ("%b %d %H:%M" if multi_day else "%H:%M")

    # Collect all tactics that appear and their total counts (for legend ordering)
    global_tactic_counts: dict[str, int] = {}
    labelled: dict[str, dict] = {}
    for sort_key, tactic_counts in timeline_raw.items():
        total = sum(tactic_counts.values())
        try:
            label = _dt.fromisoformat(sort_key).strftime(fmt)
        except ValueError:
            label = sort_key
        labelled[sort_key] = {
            "label": label,
            "count": total,
            "tactics": tactic_counts,
        }
        for t, c in tactic_counts.items():
            global_tactic_counts[t] = global_tactic_counts.get(t, 0) + c

    max_count = max(v["count"] for v in labelled.values())

    # Stable segment order: kill-chain order for known tactics, _other last
    ordered_tactics = [t for t in _MITRE_TACTICS if t in global_tactic_counts]
    if _OTHER_TACTIC in global_tactic_counts:
        ordered_tactics.append(_OTHER_TACTIC)

    def _tactic_color(t: str) -> str:
        return _MITRE_TACTIC_COLORS.get(t, _OTHER_TACTIC_COLOR)

    timeline = []
    for _, v in sorted(labelled.items()):
        total = v["count"]
        pct = round(total / max_count * 100)
        segments = []
        for t in ordered_tactics:
            tc = v["tactics"].get(t, 0)
            if tc > 0:
                segments.append(
                    {
                        "tactic": t,
                        "count": tc,
                        "pct": round(tc / total * 100) if total else 0,
                        "color": _tactic_color(t),
                    }
                )
        timeline.append(
            {
                "bucket": v["label"],
                "count": total,
                "pct": pct,
                "segments": segments,
            }
        )

    legend = [
        {
            "name": t.replace("_", " ").title() if t != _OTHER_TACTIC else "Other",
            "key": t,
            "color": _tactic_color(t),
        }
        for t in ordered_tactics
    ]

    return timeline, legend


def normalize_event_time(ts: object) -> str | None:
    """Normalize a heterogeneous event timestamp into a lexically sortable ISO-ish string.

    - ``None``/non-str/too-short (< 13 chars after strip, with no auditd marker) → ``None``
    - Strings already shaped ``YYYY-MM-DDTHH`` or ``YYYY-MM-DD HH`` are returned as-is,
      with a space separator normalized to ``T``.
    - Strings containing an ``audit(<epoch>.<frac>:<serial>)`` marker anywhere are
      converted to a UTC ISO timestamp (``YYYY-MM-DDTHH:MM:SS``) derived from the epoch.
    - Anything else → ``None``.

    Called by ``build_key_events`` and by ``parse_single_output_file``'s hour bucketing,
    which is what makes one tool's ``"… 09:…"`` and another's ``"…T09:…"`` land in the
    same bar. Does not mutate its input.
    """
    from datetime import UTC, datetime

    if not isinstance(ts, str):
        return None

    m = _RE_AUDIT_EPOCH.search(ts)
    if m:
        epoch = int(m.group(1))
        return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S")

    s = ts.strip()
    if len(s) < 13:
        return None

    if _RE_ISO_HOUR_PREFIX.match(s):
        if s[10] == " ":
            return s[:10] + "T" + s[11:]
        return s

    return None


def has_raw_output(job_id: int, job_dir: Path | None = None) -> bool:
    """True iff the job's output dir exists AND holds at least one tool-output file.

    Shares its glob/suffix logic with ``extract_all_from_raw_output`` (via
    ``_iter_output_files``) so the two never disagree about what counts as raw
    output — the case-timeline coverage notice relies on that agreement to tell
    "buckets legitimately empty" apart from "raw outputs were cleaned up".

    Pass ``job_dir`` when the tree is not on local disk — see :func:`_local_job_dir`.
    """
    job_dir = job_dir or _local_job_dir(job_id)
    if not job_dir.is_dir():
        return False
    return next(_iter_output_files(job_dir), None) is not None


def _event_computer(event: dict) -> str | None:
    """Extract a Computer/hostname from a single event dict (any tool format).

    Mirrors ``extract_timestamp``'s EVTX walk: a top-level ``Computer``/``computer`` key
    wins, else the nested ``Event.System.Computer`` shape, else Chainsaw's extra wrapper.

    Chainsaw wraps the source record one level deeper than every other tool — its hits are
    ``{group, name, level, timestamp, document: {data: {Event: {System: {...}}}}}`` — so the
    two shapes above would miss it entirely and report no host for any Chainsaw event. That is
    only cosmetic in the case key-events list, but the events-timeline marker key *includes*
    the computer, so on a multi-host Chainsaw job it would merge two hosts' alerts into one
    marker and label it with neither.
    """
    comp = event.get("Computer") or event.get("computer")
    if isinstance(comp, str) and comp:
        return comp

    for root in (event, (event.get("document") or {}).get("data") if isinstance(event.get("document"), dict) else None):
        if not isinstance(root, dict):
            continue
        evtx_sys = (root.get("Event") or {}).get("System") if isinstance(root.get("Event"), dict) else None
        if isinstance(evtx_sys, dict):
            c = evtx_sys.get("Computer")
            if isinstance(c, str) and c:
                return c

    return None


def build_key_events(
    findings: Iterable[dict],
    cap: int = 200,
) -> tuple[list[dict], int]:
    """Flatten per-finding sample events into a sorted chronological key-events list.

    Pure. Input: an iterable of plain dicts shaped
    ``{finding_id, rule_name, severity, tactic, job_id, events}`` where ``events`` is
    the already-parsed ``Finding.details`` list (``tactic`` is resolved DB-side by the
    caller, not here). Non-list ``events`` and non-dict items are skipped silently.

    Each surviving event becomes a row
    ``{ts, rule_name, severity, tactic, computer, job_id, finding_id, event}`` with
    ``ts = normalize_event_time(extract_timestamp(event))``. Rows sort lexically
    ascending by ``ts``, with undated (``ts is None``) rows grouped at the end and
    stable within each group. Returns ``(rows[:cap], total)`` where ``total`` is the
    full pre-cap row count.
    """
    items: list[dict] = []
    for finding in findings:
        events = finding.get("events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            ts = normalize_event_time(extract_timestamp(event))
            items.append(
                {
                    "ts": ts,
                    "rule_name": finding.get("rule_name"),
                    "severity": finding.get("severity"),
                    "tactic": finding.get("tactic"),
                    "computer": _event_computer(event),
                    "job_id": finding.get("job_id"),
                    "finding_id": finding.get("finding_id"),
                    "event": event,
                }
            )

    total = len(items)
    # (ts is None) sorts undated rows (True → 1) after dated ones (False → 0);
    # the ``ts or ""`` secondary key orders dated rows lexically. Python's stable
    # sort preserves insertion order within each group.
    items.sort(key=lambda it: (it["ts"] is None, it["ts"] or ""))
    return items[:cap], total
