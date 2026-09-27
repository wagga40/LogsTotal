"""Tier-1 pure-function tests for per-type entity attribute computation.

`app/intel/attributes.py::compute_attributes(value, entity_type)` returns a small
dict of per-type context (or None when nothing useful applies). It reuses the
LOLBIN set + suspicious-TLD list from config/threat_detection.yaml.
"""

from __future__ import annotations

import pytest

from app.intel.attributes import attribute_flags, attribute_keys, compute_attributes

# ── ip_address ─────────────────────────────────────────────────────────────


def test_ip_rfc1918_private():
    a = compute_attributes("10.0.0.5", "ip_address")
    assert a == {"version": "v4", "is_private": True, "category": "rfc1918"}


@pytest.mark.parametrize(
    "value, category, is_private",
    [
        ("172.16.4.2", "rfc1918", True),
        ("192.168.1.1", "rfc1918", True),
        ("fd12:3456::1", "rfc1918", True),  # unique-local, IPv6's private range
        ("240.0.0.1", "reserved", False),
        ("0.0.0.0", "reserved", False),
        ("203.0.113.9", "reserved", False),  # TEST-NET-3: documentation, not internal
        ("192.0.2.1", "reserved", False),
        ("198.18.0.1", "reserved", False),  # benchmarking
        ("2001:db8::1", "reserved", False),
        ("::", "reserved", False),
    ],
)
def test_ip_categories_name_what_the_range_is(value, category, is_private):
    """`ipaddress.is_private` is True for every special-purpose range, and it was tested
    before `is_reserved` — so `reserved` could never be reached, and `attr:rfc1918` and
    `attr:private` returned documentation and reserved addresses as internal ones."""
    a = compute_attributes(value, "ip_address")
    assert (a["category"], a["is_private"]) == (category, is_private)


def test_ip_loopback():
    a = compute_attributes("127.0.0.1", "ip_address")
    assert a["category"] == "loopback"
    assert a["is_private"] is True


def test_ip_link_local():
    assert compute_attributes("169.254.1.1", "ip_address")["category"] == "link_local"


def test_ip_multicast_is_not_private():
    a = compute_attributes("224.0.0.1", "ip_address")
    assert a["category"] == "multicast"
    assert a["is_private"] is False


def test_ip_cgnat():
    a = compute_attributes("100.64.0.1", "ip_address")
    assert a["category"] == "cgnat"
    assert a["is_private"] is True


def test_ip_public():
    a = compute_attributes("8.8.8.8", "ip_address")
    assert a == {"version": "v4", "is_private": False, "category": "public"}


def test_ipv6_public():
    a = compute_attributes("2606:4700:4700::1111", "ip_address")
    assert a["version"] == "v6"
    assert a["category"] == "public"
    assert a["is_private"] is False


def test_ipv6_loopback():
    assert compute_attributes("::1", "ip_address")["category"] == "loopback"


def test_ip_invalid_returns_none():
    assert compute_attributes("not-an-ip", "ip_address") is None


# ── hash ───────────────────────────────────────────────────────────────────


def test_hash_md5():
    assert compute_attributes("A" * 32, "hash") == {"algorithm": "md5", "length": 32}


def test_hash_sha1():
    assert compute_attributes("b" * 40, "hash") == {"algorithm": "sha1", "length": 40}


def test_hash_sha256():
    assert compute_attributes("C" * 64, "hash") == {"algorithm": "sha256", "length": 64}


def test_hash_sha512():
    assert compute_attributes("d" * 128, "hash") == {"algorithm": "sha512", "length": 128}


def test_hash_unknown_length_returns_none():
    assert compute_attributes("abc", "hash") is None


# ── domain ─────────────────────────────────────────────────────────────────


def test_domain_normal():
    a = compute_attributes("mail.google.com", "domain")
    assert a["tld"] == "com"
    assert a["suspicious_tld"] is False
    assert a["looks_dga"] is False
    assert a["label_count"] == 3


def test_domain_suspicious_tld():
    a = compute_attributes("badstuff.tk", "domain")
    assert a["tld"] == "tk"
    assert a["suspicious_tld"] is True


def test_domain_dga_high_entropy_label():
    # 20 distinct chars in the leftmost label -> entropy >= 4.0 and length >= 12
    a = compute_attributes("x7k9q2m4p8w1z5b3n6v0.com", "domain")
    assert a["looks_dga"] is True


def test_domain_short_label_not_dga():
    assert compute_attributes("google.com", "domain")["looks_dga"] is False


# ── user ───────────────────────────────────────────────────────────────────


def test_user_machine_account():
    a = compute_attributes("WS01$", "user")
    assert a["is_machine_account"] is True


def test_user_privileged_admin():
    assert compute_attributes("Administrator", "user")["looks_privileged"] is True


def test_user_privileged_service_prefix():
    assert compute_attributes("CORP\\svc-backup", "user")["looks_privileged"] is True


def test_user_normal_not_privileged():
    a = compute_attributes("jdoe", "user")
    assert a["is_machine_account"] is False
    assert a["looks_privileged"] is False


# ── executable ─────────────────────────────────────────────────────────────


def test_executable_gtfobin():
    assert compute_attributes("nmap", "executable") == {"is_lolbin": False, "is_gtfobin": True}


def test_executable_gtfobin_negative():
    attrs = compute_attributes("sshd", "executable")
    assert attrs["is_gtfobin"] is False


def test_gtfobin_reaches_the_attributes_card():
    """It was the one the hand-written Jinja chain silently omitted, so it is named."""
    assert attribute_keys('{"is_gtfobin": true}') == ["gtfobin"]


def test_executable_lolbin():
    # certutil.exe is in the LOLBAS set seeded in config/threat_detection.yaml
    assert compute_attributes("certutil.exe", "executable") == {"is_lolbin": True, "is_gtfobin": False}


def test_executable_non_lolbin():
    assert compute_attributes("totally-custom-app.exe", "executable") == {"is_lolbin": False, "is_gtfobin": False}


# ── service ────────────────────────────────────────────────────────────────


def test_service_system_path_keyword():
    a = compute_attributes(r"C:\Windows\System32\svchost.exe", "service")
    assert a["looks_signed_keyword"] is True


def test_service_unusual_path():
    a = compute_attributes(r"C:\Users\bob\AppData\evil.exe", "service")
    assert a["looks_signed_keyword"] is False


# ── general ────────────────────────────────────────────────────────────────


def test_unknown_type_or_empty_returns_none():
    assert compute_attributes("anything", "computer") is None
    assert compute_attributes("", "ip_address") is None
    assert compute_attributes(None, "hash") is None


# ── attribute_keys (the Attributes card on the entity Overview tab) ────────
#
# ── attribute_keys (the entity Overview's Attributes card) ─────────────────
# Facts, not labels: the card shows what the engine derived, the tags show what a rule
# wrote, and the gap between them is the diagnosis. Replaced `attribute_keys`, which read
# the built-in rule registry the seed file retired.


def test_attribute_keys_lists_the_subtype_first_then_the_flags_sorted():
    blob = '{"category": "rfc1918", "is_private": true}'
    assert attribute_keys(blob) == ["rfc1918", "private"]
    assert attribute_keys('{"looks_dga": true, "suspicious_tld": true, "tld": "tk"}') == ["dga", "suspicious_tld"]


def test_a_false_flag_produces_nothing():
    assert attribute_keys('{"is_lolbin": false}') == []


def test_private_is_a_fact_even_though_no_rule_writes_it():
    """The one attribute with no built-in rule behind it — it is implied by every private
    category, so a tag for it would say the same thing twice. The card still shows it."""
    assert "private" in attribute_keys('{"category": "loopback", "is_private": true}')


def test_it_agrees_with_the_graph_payload_helpers():
    blob = '{"is_lolbin": true, "is_gtfobin": true}'
    from app.json_utils import loads

    assert set(attribute_keys(blob)) == set(attribute_flags(loads(blob)))


def test_malformed_input_yields_nothing_and_never_raises():
    assert attribute_keys("not-json{") == []
    assert attribute_keys(None) == []
    assert attribute_keys("") == []
    assert attribute_keys("[1, 2]") == []


# ── attribute_flags / attribute_subtype (graph payload) ────────────────────


def test_flags_and_subtype_cover_attr_filters_exactly():
    """Both directions. A key in neither is a `label:` filter the graph silently ignores.

    The relationship graph evaluates `attr:`/`label:` client-side against a bitfield plus
    one enum slot; that is only sound while the two together span `ATTR_FILTERS`. Adding a
    filter key without a home here would make the chip clickable on the dashboard and inert
    on the graph — the exact asymmetry app/intel/labels.py was written to end.
    """
    from app.intel.attributes import attribute_flags, attribute_subtype
    from app.intel.queries import ATTR_FILTERS

    booleans = {k for k, (_f, v) in ATTR_FILTERS.items() if v is True}
    categoricals = set(ATTR_FILTERS) - booleans

    for key in booleans:
        field, _value = ATTR_FILTERS[key]
        assert key in attribute_flags({field: True}), f"{key} is not reachable via attribute_flags"
        assert attribute_subtype({field: True}) is None or key not in categoricals

    for key in categoricals:
        field, value = ATTR_FILTERS[key]
        assert attribute_subtype({field: value}) == key, f"{key} is not reachable via attribute_subtype"

    assert booleans | categoricals == set(ATTR_FILTERS)


def test_flags_read_real_computed_attributes():
    from app.intel.attributes import attribute_flags, attribute_subtype

    exe = compute_attributes("certutil.exe", "executable")
    assert "lolbin" in attribute_flags(exe)

    ip = compute_attributes("10.0.0.5", "ip_address")
    assert attribute_subtype(ip) == "rfc1918"
    assert "private" in attribute_flags(ip)

    digest = compute_attributes("a" * 64, "hash")
    assert attribute_subtype(digest) == "sha256"


def test_flags_never_raise_on_junk():
    from app.intel.attributes import attribute_flags, attribute_subtype

    for junk in (None, {}, "not a dict", 42, []):
        assert attribute_flags(junk) == frozenset()
        assert attribute_subtype(junk) is None
