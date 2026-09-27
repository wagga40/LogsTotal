"""
Threat Detection engine — behavioral heuristic checks on finding detail events.
Pure Python module (no FastAPI/Huey imports). Follows app/analytics_fields.py pattern.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from app.config import settings
from app.constants import SEVERITY_RANK as _SEVERITY_RANK
from app.yaml_utils import safe_load as yaml_safe_load

# ── Severity ordering ────────────────────────────────────────────────────────


def _max_severity(*severities: str) -> str:
    best = "informational"
    for s in severities:
        if _SEVERITY_RANK.get(s, 99) < _SEVERITY_RANK.get(best, 99):
            best = s
    return best


# ── Shannon entropy ──────────────────────────────────────────────────────────


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


# ── Typosquat helpers ────────────────────────────────────────────────────────


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (stdlib only, O(m*n) DP)."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _has_visual_trick(name: str, target: str) -> bool:
    """Check if the difference between name and target looks like deliberate visual
    confusion: digit/letter swaps (0↔o, 1↔l, 5↔s), char transposition, insertion
    of similar-looking chars, etc.  Returns True if it smells intentional."""
    # Strip .exe for comparison
    n = name.removesuffix(".exe")
    t = target.removesuffix(".exe")
    if not n or not t:
        return False
    # Quick length check — typosquats are usually within ±2 chars
    if abs(len(n) - len(t)) > 2:
        return False
    # Visual substitution pairs (lowercase)
    _VISUAL_PAIRS = {
        ("0", "o"),
        ("o", "0"),
        ("1", "l"),
        ("l", "1"),
        ("1", "i"),
        ("i", "1"),
        ("5", "s"),
        ("s", "5"),
        ("8", "b"),
        ("b", "8"),
        ("rn", "m"),
        ("m", "rn"),
        ("vv", "w"),
        ("w", "vv"),
    }
    # Check single-char visual swaps
    if len(n) == len(t):
        diffs = [(i, n[i], t[i]) for i in range(len(n)) if n[i] != t[i]]
        if len(diffs) <= 2:
            for _, nc, tc in diffs:
                if (nc, tc) in _VISUAL_PAIRS:
                    return True
    # Check transposition (adjacent char swap): ssms↔smss, expolrer↔explorer
    if len(n) == len(t):
        for i in range(len(n) - 1):
            swapped = n[:i] + n[i + 1] + n[i] + n[i + 2 :]
            if swapped == t:
                return True
    # Check single char insertion/deletion
    if abs(len(n) - len(t)) == 1:
        longer, shorter = (n, t) if len(n) > len(t) else (t, n)
        for i in range(len(longer)):
            if longer[:i] + longer[i + 1 :] == shorter:
                return True
    return False


# ── Excerpt helpers ──────────────────────────────────────────────────────────


def _smart_excerpt(val: str, match_start: int, match_end: int, max_len: int = 8192) -> str:
    """Return the full matched field value for analyst visibility.

    Not a short excerpt: long command lines and encoded payloads are the evidence, so
    CTI/forensics workflows get the full value unless it is excessively large.
    """
    text = (val or "").strip()
    if len(text) <= max_len:
        return text

    # Keep head + tail so analysts can still inspect long payloads.
    marker = " ...[truncated]... "
    if max_len <= len(marker) + 2:
        return text[:max_len]
    half = (max_len - len(marker)) // 2
    tail = max_len - len(marker) - half
    return text[:half] + marker + text[-tail:]


# ── Config loader ────────────────────────────────────────────────────────────

_cached: dict | None = None


def _compile_config(raw: dict) -> dict:
    """Parse raw YAML dict into a structured config with compiled regex patterns."""
    categories = {}
    for key, cat in raw.get("categories", {}).items():
        compiled_checks = []
        for check in cat.get("checks", []):
            ctype = check["type"]
            compiled = dict(check)  # shallow copy

            if ctype == "regex":
                compiled_patterns = []
                for p in check.get("patterns", []):
                    compiled_patterns.append(
                        {
                            "name": p["name"],
                            # IGNORECASE for every pattern rather than relying on each YAML
                            # entry to carry `(?i)`: one that forgot would miss
                            # `invoice.pdf.EXE` — exactly the casing an attacker would use.
                            # No shipped pattern depends on case-sensitive matching.
                            "regex": re.compile(p["pattern"], re.IGNORECASE),
                            "severity": p.get("severity", cat.get("default_severity", "medium")),
                        }
                    )
                compiled["compiled_patterns"] = compiled_patterns

            elif ctype == "basename_in_set":
                compiled["value_set"] = frozenset(v.lower() for v in check.get("values", []))

            elif ctype == "keyword_in_value":
                compiled["keyword_list"] = [v.lower() for v in check.get("values", [])]

            elif ctype == "port_in_set":
                compiled["port_set"] = frozenset(int(v) for v in check.get("values", []))

            elif ctype == "masquerade":
                compiled["binary_set"] = frozenset(v.lower() for v in check.get("system_binaries", []))
                compiled["legit_paths"] = [p.lower() for p in check.get("legitimate_paths", [])]

            elif ctype == "typosquat":
                compiled["target_set"] = frozenset(v.lower() for v in check.get("targets", []))
                compiled["exclude_set"] = frozenset(v.lower() for v in check.get("exclude", []))
                compiled["max_distance"] = check.get("max_distance", 2)
                compiled["min_length"] = check.get("min_length", 4)

            compiled_checks.append(compiled)

        categories[key] = {
            "label": cat["label"],
            "description": cat.get("description", ""),
            "default_severity": cat.get("default_severity", "medium"),
            "checks": compiled_checks,
        }
    return categories


def load_threat_config(path: Path | None = None) -> dict:
    """Load and compile threat detection config from YAML."""
    p = path or settings.threat_detection_config_path
    if not p.is_absolute():
        p = Path.cwd() / p
    if not p.exists():
        return {}
    text = p.read_text(encoding="utf-8")
    data = yaml_safe_load(text)
    if not isinstance(data, dict):
        return {}
    return _compile_config(data)


def get_threat_config() -> dict:
    """Return cached threat detection config, loading from YAML on first call."""
    global _cached
    if _cached is None:
        _cached = load_threat_config()
    return _cached


# ── Check type dispatch ──────────────────────────────────────────────────────
# Each handler returns {tag: (count, severity, matched_value)}
# - tag is the detection NAME (uppercase)
# - matched_value is the actual data that caused the match

_MatchResult = dict[str, tuple[int, str, str]]


def _check_regex(check: dict, scan_dicts: list[dict]) -> _MatchResult:
    """Returns {PATTERN_NAME: (1, severity, matched_excerpt)} for matched patterns."""
    results: _MatchResult = {}
    fields = check.get("fields", [])
    for pat_info in check.get("compiled_patterns", []):
        name = pat_info["name"].upper()
        regex = pat_info["regex"]
        severity = pat_info["severity"]
        for d in scan_dicts:
            if name in results:
                break
            for fld in fields:
                val = d.get(fld)
                if isinstance(val, str):
                    m = regex.search(val)
                    if m:
                        excerpt = _smart_excerpt(val, m.start(), m.end())
                        results[name] = (1, severity, excerpt)
                        break
    return results


def _check_basename_in_set(check: dict, scan_dicts: list[dict]) -> _MatchResult:
    """Returns {BINARY_NAME: (1, severity, full_path)} for matched basenames."""
    results: _MatchResult = {}
    fields = check.get("fields", [])
    value_set = check.get("value_set", frozenset())
    severity = check.get("severity", check.get("default_severity", "high"))
    for d in scan_dicts:
        for fld in fields:
            val = d.get(fld)
            if isinstance(val, str) and val.strip():
                basename = os.path.basename(val.replace("\\", "/")).strip().lower()
                if basename in value_set:
                    path_display = val.strip()
                    if len(path_display) > 80:
                        path_display = "..." + path_display[-77:]
                    results[basename.upper()] = (1, severity, path_display)
    return results


def _check_keyword_in_value(check: dict, scan_dicts: list[dict]) -> _MatchResult:
    """Returns {NAME: (1, severity, matched_context)} for matched keywords."""
    results: _MatchResult = {}
    fields = check.get("fields", [])
    keywords = check.get("keyword_list", [])
    severity = check.get("severity", check.get("default_severity", "medium"))
    name_prefix = check.get("name", "KEYWORD").upper()
    for d in scan_dicts:
        for fld in fields:
            val = d.get(fld)
            if not isinstance(val, str):
                continue
            val_lower = val.lower()
            for kw in keywords:
                if kw in val_lower:
                    tag = f"{name_prefix}"
                    idx = val_lower.find(kw)
                    excerpt = _smart_excerpt(val, idx, idx + len(kw))
                    results[tag] = (1, severity, excerpt)
    return results


def _check_port_in_set(check: dict, scan_dicts: list[dict]) -> _MatchResult:
    """Returns {C2_PORT: (1, severity, field=value)} for matched ports."""
    results: _MatchResult = {}
    fields = check.get("fields", [])
    port_set = check.get("port_set", frozenset())
    severity = check.get("severity", check.get("default_severity", "medium"))
    for d in scan_dicts:
        for fld in fields:
            val = d.get(fld)
            if val is None:
                continue
            try:
                port = int(val)
            except (ValueError, TypeError):
                continue
            if port in port_set:
                results["C2_PORT"] = (1, severity, f"{fld}={port}")
    return results


def _check_entropy(check: dict, scan_dicts: list[dict]) -> _MatchResult:
    """Returns {NAME: (1, severity, value)} if entropy exceeds threshold."""
    results: _MatchResult = {}
    fields = check.get("fields", [])
    threshold = check.get("threshold", 3.5)
    min_length = check.get("min_length", 15)
    name = check.get("name", "HIGH_ENTROPY").upper()
    severity = check.get("severity", check.get("default_severity", "medium"))
    for d in scan_dicts:
        for fld in fields:
            val = d.get(fld)
            if isinstance(val, str) and len(val) >= min_length:
                ent = _shannon_entropy(val)
                if ent > threshold:
                    display = val if len(val) <= 60 else val[:57] + "..."
                    results[name] = (1, severity, display)
                    return results  # one match is enough per event
    return results


def _check_masquerade(check: dict, scan_dicts: list[dict]) -> _MatchResult:
    """Returns {MASQUERADE: (1, severity, full_path)} for masquerading processes."""
    results: _MatchResult = {}
    fields = check.get("fields", [])
    binary_set = check.get("binary_set", frozenset())
    legit_paths = check.get("legit_paths", [])
    severity = check.get("severity", check.get("default_severity", "high"))
    for d in scan_dicts:
        for fld in fields:
            val = d.get(fld)
            if not isinstance(val, str) or not val.strip():
                continue
            normalized = val.replace("\\", "/").strip().lower()
            basename = os.path.basename(normalized)
            if basename in binary_set:
                win_path = val.strip().lower().replace("/", "\\")
                is_legit = any(win_path.startswith(lp) or win_path == lp.rstrip("\\") for lp in legit_paths)
                if not is_legit:
                    results["MASQUERADE"] = (1, severity, val.strip())
    return results


def _check_typosquat(check: dict, scan_dicts: list[dict]) -> _MatchResult:
    """Flag executables whose names look like visual tricks on known system binaries
    (digit-letter swaps, transpositions, extra/missing chars)."""
    results: _MatchResult = {}
    fields = check.get("fields", [])
    target_set = check.get("target_set", frozenset())
    exclude_set = check.get("exclude_set", frozenset())
    max_dist = check.get("max_distance", 2)
    min_len = check.get("min_length", 4)
    severity = check.get("severity", check.get("default_severity", "high"))
    targets_by_len = check.get("_targets_by_len")
    if targets_by_len is None:
        targets_by_len = {}
        for t in target_set:
            targets_by_len.setdefault(len(t), []).append(t)
        check["_targets_by_len"] = targets_by_len
    for d in scan_dicts:
        for fld in fields:
            val = d.get(fld)
            if not isinstance(val, str) or not val.strip():
                continue
            basename = os.path.basename(val.replace("\\", "/")).strip().lower()
            if not basename or len(basename) < min_len:
                continue
            if basename in target_set or basename in exclude_set:
                continue
            blen = len(basename)
            candidates = []
            for offset in range(-max_dist, max_dist + 1):
                candidates.extend(targets_by_len.get(blen + offset, ()))
            if not candidates:
                continue
            for target in candidates:
                dist = _edit_distance(basename, target)
                if 0 < dist <= max_dist and _has_visual_trick(basename, target):
                    path_display = val.strip()
                    if len(path_display) > 80:
                        path_display = "..." + path_display[-77:]
                    tag = f"TYPOSQUAT_{target.removesuffix('.exe').upper()}"
                    results[tag] = (1, severity, f"{basename} (looks like {target}) at {path_display}")
                    break
    return results


_CHECK_DISPATCH = {
    "regex": _check_regex,
    "basename_in_set": _check_basename_in_set,
    "keyword_in_value": _check_keyword_in_value,
    "port_in_set": _check_port_in_set,
    "entropy": _check_entropy,
    "masquerade": _check_masquerade,
    "typosquat": _check_typosquat,
}


# ── Main detection entry point ───────────────────────────────────────────────


class ThreatAccumulator:
    """Incremental form of :func:`compute_threat_detection`.

    Lets the analytics pass feed events in as they are parsed instead of materialising
    every matched event's scan dicts first — on a large job that list would be the single
    biggest allocation the worker makes.

    Not thread-safe: the caller serialises ``add()``.
    """

    __slots__ = ("_accum", "_cat_checks", "_config")

    def __init__(self) -> None:
        self._config = get_threat_config()
        # Pre-build (cat_key, checks_list) to avoid dict iteration overhead per event.
        self._cat_checks: list[tuple[str, list[dict]]] = [(cat_key, cat_cfg["checks"]) for cat_key, cat_cfg in (self._config or {}).items()]
        self._accum: dict[str, dict[tuple[str, str], dict[str, Any]]] = {k: {} for k in (self._config or {})}

    def add(self, scan_dicts: list[dict]) -> None:
        """Fold one event's scan dicts in."""
        if not self._config:
            return
        for cat_key, checks in self._cat_checks:
            event_hits: set[tuple[str, str, str]] = set()

            for check in checks:
                handler = _CHECK_DISPATCH.get(check["type"])
                if handler is None:
                    continue
                matches = handler(check, scan_dicts)
                for tag, (_count, severity, matched_val) in matches.items():
                    event_hits.add((tag, severity, matched_val))

            cat_accum = self._accum[cat_key]
            for tag, severity, matched_val in event_hits:
                key = (tag, matched_val)
                entry = cat_accum.get(key)
                if entry is None:
                    cat_accum[key] = {"count": 1, "severity": severity}
                else:
                    entry["count"] += 1

    def result(self) -> dict:
        """The same dict :func:`compute_threat_detection` has always returned."""
        if not self._config:
            return {"total_indicators": 0, "total_categories": 0, "categories": {}}

        categories = {}
        total_indicators = 0
        total_categories = 0

        for cat_key, cat_cfg in self._config.items():
            cat_accum = self._accum.get(cat_key, {})
            if not cat_accum:
                continue

            indicators = []
            cat_severity = "informational"
            cat_total = 0

            for (tag, value), info in sorted(
                cat_accum.items(),
                key=lambda x: (-x[1]["count"], x[0][0], x[0][1]),
            ):
                indicators.append(
                    {
                        "tag": tag,
                        "count": info["count"],
                        "severity": info["severity"],
                        "value": value,
                    }
                )
                cat_severity = _max_severity(cat_severity, info["severity"])
                cat_total += info["count"]

            categories[cat_key] = {
                "label": cat_cfg["label"],
                "description": cat_cfg["description"],
                "severity": cat_severity,
                "indicators": indicators,
                "total": cat_total,
            }
            total_indicators += cat_total
            total_categories += 1

        return {
            "total_indicators": total_indicators,
            "total_categories": total_categories,
            "categories": categories,
        }


def compute_threat_detection(all_scan_events: list[list[dict]]) -> dict:
    """
    Run all threat detection checks against scan events.

    Indicators are grouped by (tag, value): only events with the same tag AND
    the same matched value are aggregated (xN).  Different values produce
    separate indicator rows.

    Thin wrapper over :class:`ThreatAccumulator`, for a caller that genuinely has the
    whole list.

    Returns:
        Dict ready for JSON serialization with categories, indicators, and totals.
    """
    acc = ThreatAccumulator()
    for scan_dicts in all_scan_events:
        acc.add(scan_dicts)
    return acc.result()
