"""Per-type entity attributes — small JSON context computed at entity-creation time.

Pure-ish module: no FastAPI / Huey imports. It does read the shared threat-detection
config (LOLBIN set + suspicious-TLD list) as the single source of truth, mirroring how
``_compute_analytics_data`` reuses ``app/analytics_fields.py``.

``compute_attributes(value, entity_type)`` returns a small dict (JSON-serialisable) or
``None`` when nothing useful applies. Stored via ``app.json_utils.dumps`` on
``Entity.attributes_json`` — the same serializer the ``attr:`` LIKE filters in
``queries.ATTR_FILTERS`` assume.
"""

from __future__ import annotations

import ipaddress
import re

from app.threat_detection import _shannon_entropy, get_threat_config

# DGA heuristic thresholds (leftmost label).
_DGA_MIN_LEN = 12
_DGA_MIN_ENTROPY = 4.0

_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
# The ranges that are private in the sense an analyst means — internal addressing. Named,
# because `ipaddress.is_private` is True for every special-purpose block too (documentation,
# benchmarking, 0/8, 240/4, …), and testing it before `is_reserved` made `reserved`
# unreachable and called TEST-NET addresses internal.
_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))

# Privileged-account name hints. svc-/sa_ are service-account prefixes.
_PRIV_USER_RE = re.compile(r"admin|administrator|\broot\b|svc-|sa_", re.IGNORECASE)

# System paths that imply a trusted/likely-signed binary backing a service.
_SIGNED_PATH_RE = re.compile(r"system32|syswow64|\\windows\\|/windows/|program files", re.IGNORECASE)

_HASH_ALGOS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


# ── Config-derived sets (cached, single source of truth) ───────────────────


_lolbins_cache: frozenset[str] | None = None
_gtfobins_cache: frozenset[str] | None = None
_susp_tld_cache: frozenset[str] | None = None


def _basename_set_for(category: str) -> frozenset[str]:
    out: set[str] = set()
    cfg = get_threat_config()
    cat = cfg.get(category, {})
    for check in cat.get("checks", []):
        if check.get("type") == "basename_in_set":
            out |= set(check.get("value_set", frozenset()))
    return frozenset(out)


def _lolbin_set() -> frozenset[str]:
    """LOLBAS basenames from the ``lolbin_usage`` category's basename_in_set check."""
    global _lolbins_cache
    if _lolbins_cache is None:
        _lolbins_cache = _basename_set_for("lolbin_usage")
    return _lolbins_cache


def _gtfobin_set() -> frozenset[str]:
    """GTFOBins basenames from the ``gtfobins_usage`` category's basename_in_set check."""
    global _gtfobins_cache
    if _gtfobins_cache is None:
        _gtfobins_cache = _basename_set_for("gtfobins_usage")
    return _gtfobins_cache


def _suspicious_tlds() -> frozenset[str]:
    """Suspicious TLDs (``.tk`` etc.) from the ``suspicious_tld`` keyword check."""
    global _susp_tld_cache
    if _susp_tld_cache is None:
        out: set[str] = set()
        for cat in get_threat_config().values():
            for check in cat.get("checks", []):
                if check.get("name") == "suspicious_tld" or "suspicious_tld" in str(check.get("name", "")):
                    out |= {t.lstrip(".").lower() for t in check.get("keyword_list", [])}
        _susp_tld_cache = frozenset(out)
    return _susp_tld_cache


# ── Per-type attribute builders ────────────────────────────────────────────


def _ip_attrs(value: str) -> dict | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    version = "v6" if addr.version == 6 else "v4"
    if addr.is_loopback:
        category = "loopback"
    elif addr.is_link_local:
        category = "link_local"
    elif addr.is_multicast:
        category = "multicast"
    elif addr.version == 4 and addr in _CGNAT_V4:
        category = "cgnat"
    elif any(addr.version == net.version and addr in net for net in _PRIVATE_NETS):
        category = "rfc1918"
    elif addr.is_private or addr.is_reserved or addr.is_unspecified:
        category = "reserved"
    else:
        category = "public"
    is_private = category in ("rfc1918", "loopback", "link_local", "cgnat")
    return {"version": version, "is_private": is_private, "category": category}


def _hash_attrs(value: str) -> dict | None:
    algo = _HASH_ALGOS.get(len(value))
    if algo is None:
        return None
    return {"algorithm": algo, "length": len(value)}


def _domain_attrs(value: str) -> dict | None:
    v = value.strip().lower().rstrip(".")
    if not v or "." not in v:
        return None
    labels = v.split(".")
    tld = labels[-1]
    leftmost = labels[0]
    looks_dga = len(leftmost) >= _DGA_MIN_LEN and _shannon_entropy(leftmost) >= _DGA_MIN_ENTROPY
    return {
        "tld": tld,
        "suspicious_tld": tld in _suspicious_tlds(),
        "looks_dga": looks_dga,
        "label_count": len(labels),
    }


def _user_attrs(value: str) -> dict | None:
    v = value.strip()
    if not v:
        return None
    return {
        "is_machine_account": v.endswith("$"),
        "looks_privileged": bool(_PRIV_USER_RE.search(v)),
    }


def _executable_attrs(value: str) -> dict | None:
    name = value.strip().lower()
    if not name:
        return None
    return {"is_lolbin": name in _lolbin_set(), "is_gtfobin": name in _gtfobin_set()}


def _service_attrs(value: str) -> dict | None:
    v = value.strip()
    if not v:
        return None
    return {"looks_signed_keyword": bool(_SIGNED_PATH_RE.search(v))}


_DISPATCH = {
    "ip_address": _ip_attrs,
    "hash": _hash_attrs,
    "domain": _domain_attrs,
    "user": _user_attrs,
    "executable": _executable_attrs,
    "service": _service_attrs,
}


def compute_attributes(value: str | None, entity_type: str) -> dict | None:
    """Return a small per-type attribute dict for an entity, or None if nothing applies."""
    if not value or not isinstance(value, str):
        return None
    fn = _DISPATCH.get(entity_type)
    if fn is None:
        return None
    return fn(value)


# ── Display chips (dashboard table / entity detail) ────────────────────────


def attribute_flags(attrs: dict | None) -> frozenset[str]:
    """Every boolean `attr:` key an attributes dict satisfies.

    Boolean keys only — the ones whose ``ATTR_FILTERS`` value is ``True``. The categorical
    ones (`category`, `algorithm`) collapse to a single value per entity and are handled by
    :func:`attribute_subtype`, so the two together cover ``ATTR_FILTERS`` exactly. That
    coverage is what lets the relationship graph evaluate ``attr:``/``label:`` filters
    client-side with no round trip, and it is pinned by a set-equality test in both
    directions in ``tests/test_intel_attributes.py``.

    Never raises: a malformed blob yields an empty set, the same contract
    ``attribute_keys`` below has.
    """
    from app.intel.queries import ATTR_FILTERS

    if not isinstance(attrs, dict):
        return frozenset()
    return frozenset(key for key, (field, expected) in ATTR_FILTERS.items() if expected is True and attrs.get(field) is True)


def attribute_subtype(attrs: dict | None) -> str | None:
    """The single categorical `attr:` key an attributes dict satisfies, if any.

    ``category`` (IP ranges) and ``algorithm`` (hash widths) are mutually exclusive within
    themselves *and* with each other — an entity is one or the other, never both — so one
    enum slot per node is enough on the wire. Returns the ``ATTR_FILTERS`` key, not the raw
    field value, so callers never have to know which field it came from.
    """
    from app.intel.queries import ATTR_FILTERS

    if not isinstance(attrs, dict):
        return None
    for key, (field, expected) in ATTR_FILTERS.items():
        if expected is True:
            continue
        if attrs.get(field) == expected:
            return key
    return None


def attribute_keys(attributes_json: str | None) -> list[str]:
    """Every `attr:` key this entity's stored attributes satisfy: the subtype first, then the flags, sorted.

    What the entity Overview's Attributes card renders — *facts*, not labels. The card says
    what the attribute engine computed for this entity; the tags in the header say what a
    rule wrote down. Usually the two agree, and when they do not the gap is the answer: a
    backfill that has not run, a built-in somebody edited or disabled, a tag somebody
    deleted. Rendering the card from the rules would hide precisely that, which is why it
    reads `attributes_json` and nothing else, and shows the keys themselves, each linking to
    the `attr:` filter it *is*.

    Never raises: a malformed blob yields no keys rather than a 500 on the page.
    """
    from app.json_utils import loads as _loads

    if not attributes_json:
        return []
    try:
        attrs = _loads(attributes_json)
    except Exception:
        return []
    if not isinstance(attrs, dict):
        return []
    subtype = attribute_subtype(attrs)
    return ([subtype] if subtype else []) + sorted(attribute_flags(attrs))
