"""Tier-1 tests for the SSRF guard in app/intel/live_enrichment.py.

The DNS resolver is injected so these tests never touch the network.
"""

from __future__ import annotations

from app.intel.live_enrichment import (
    _build_headers,
    _ip_is_blocked,
    resolve_and_validate_url,
    validate_api_template,
)
from app.network.url_pinning import pin_url_to_ip as _pin_url_to_ip


def _resolver(*ips):
    return lambda host: list(ips)


def validate_enrichment_url(url, **kw):
    """(ok, reason) — the pinned IP is asserted separately below."""
    ok, reason, _ = resolve_and_validate_url(url, **kw)
    return ok, reason


# ── _ip_is_blocked (pure) ──────────────────────────────────────────────────


def test_blocks_private_loopback_linklocal_metadata():
    assert _ip_is_blocked("127.0.0.1") is True
    assert _ip_is_blocked("10.0.0.1") is True
    assert _ip_is_blocked("192.168.1.1") is True
    assert _ip_is_blocked("169.254.169.254") is True  # cloud metadata
    assert _ip_is_blocked("::1") is True
    assert _ip_is_blocked("0.0.0.0") is True


def test_allows_public():
    assert _ip_is_blocked("8.8.8.8") is False
    assert _ip_is_blocked("1.1.1.1") is False
    assert _ip_is_blocked("2606:4700:4700::1111") is False


def test_invalid_ip_is_blocked():
    assert _ip_is_blocked("not-an-ip") is True


# ── resolve_and_validate_url ───────────────────────────────────────────────


def test_public_https_url_ok():
    ok, _ = validate_enrichment_url("https://api.example.com/x", resolver=_resolver("8.8.8.8"))
    assert ok is True


def test_rejects_non_http_scheme():
    ok, reason = validate_enrichment_url("file:///etc/passwd", resolver=_resolver("8.8.8.8"))
    assert ok is False
    assert "scheme" in reason.lower()


def test_rejects_missing_host():
    ok, _ = validate_enrichment_url("https:///nohostpath", resolver=_resolver("8.8.8.8"))
    assert ok is False


def test_rejects_ip_literal_private():
    ok, reason = validate_enrichment_url("https://10.0.0.5/x", resolver=_resolver("8.8.8.8"))
    assert ok is False
    assert "private" in reason.lower() or "blocked" in reason.lower()


def test_rejects_metadata_ip_literal():
    ok, _ = validate_enrichment_url("http://169.254.169.254/latest/meta-data/", resolver=_resolver("8.8.8.8"))
    assert ok is False


def test_rejects_host_resolving_to_private():
    # DNS-rebinding style: hostname resolves to an internal IP
    ok, _ = validate_enrichment_url("https://sneaky.example.com/", resolver=_resolver("127.0.0.1"))
    assert ok is False


def test_rejects_when_any_resolved_ip_is_private():
    ok, _ = validate_enrichment_url("https://mixed.example.com/", resolver=_resolver("8.8.8.8", "10.0.0.1"))
    assert ok is False


def test_resolver_failure_is_blocked():
    def boom(host):
        raise OSError("dns fail")

    ok, _ = validate_enrichment_url("https://nope.example.com/", resolver=boom)
    assert ok is False


def test_allowlist_enforced_when_provided():
    ok, reason = validate_enrichment_url("https://evil.com/x", allowed_hosts=["virustotal.com"], resolver=_resolver("8.8.8.8"))
    assert ok is False
    assert "allow" in reason.lower()


def test_allowlist_suffix_match_ok():
    ok, _ = validate_enrichment_url("https://www.virustotal.com/api/v3/x", allowed_hosts=["virustotal.com"], resolver=_resolver("8.8.8.8"))
    assert ok is True


def test_allowlist_exact_match_ok():
    ok, _ = validate_enrichment_url("https://virustotal.com/x", allowed_hosts=["virustotal.com"], resolver=_resolver("8.8.8.8"))
    assert ok is True


def test_allowlist_no_partial_suffix_bypass():
    # "notvirustotal.com" must NOT pass an allowlist of "virustotal.com"
    ok, _ = validate_enrichment_url("https://notvirustotal.com/x", allowed_hosts=["virustotal.com"], resolver=_resolver("8.8.8.8"))
    assert ok is False


# ── CGNAT / non-global blocking ────────────────────────────────────────────


def test_blocks_cgnat_and_other_nonglobal():
    assert _ip_is_blocked("100.64.0.1") is True  # RFC 6598 carrier-grade NAT
    assert _ip_is_blocked("100.127.255.255") is True
    assert _ip_is_blocked("::ffff:10.0.0.1") is True  # IPv4-mapped private


def test_rejects_host_resolving_to_cgnat():
    ok, reason = validate_enrichment_url("https://rebind.example.com/", resolver=_resolver("100.64.1.2"))
    assert ok is False
    assert "blocked" in reason.lower()


# ── IP pinning (DNS-rebinding TOCTOU) ──────────────────────────────────────


def test_resolve_and_validate_returns_pinned_ip():
    ok, _reason, pinned = resolve_and_validate_url("https://api.example.com/x", resolver=_resolver("8.8.8.8", "1.1.1.1"))
    assert ok is True
    assert pinned == "8.8.8.8"  # first validated address


def test_resolve_and_validate_blocks_and_returns_no_ip():
    ok, _reason, pinned = resolve_and_validate_url("https://api.example.com/x", resolver=_resolver("8.8.8.8", "10.0.0.1"))
    assert ok is False
    assert pinned is None


def test_pin_url_rewrites_host_but_keeps_hostname_header():
    connect, host_header = _pin_url_to_ip("https://api.example.com/v3/x?y=1", "8.8.8.8")
    assert connect == "https://8.8.8.8/v3/x?y=1"
    assert host_header == "api.example.com"


def test_pin_url_preserves_port_and_brackets_ipv6():
    connect, host_header = _pin_url_to_ip("https://api.example.com:8443/x", "2606:4700::1111")
    assert connect == "https://[2606:4700::1111]:8443/x"
    assert host_header == "api.example.com:8443"


# ── api_template save-time validation ──────────────────────────────────────


def test_api_template_accepts_public_https():
    ok, _ = validate_api_template("https://api.example.com/{value}", None)
    assert ok is True


def test_api_template_rejects_non_http_scheme():
    ok, reason = validate_api_template("ftp://api.example.com/{value}", None)
    assert ok is False
    assert "scheme" in reason.lower()


def test_api_template_rejects_private_ip_literal():
    ok, _ = validate_api_template("http://169.254.169.254/{value}", None)
    assert ok is False


def test_api_template_enforces_known_provider_allowlist():
    ok, reason = validate_api_template("https://evil.example.com/{value}", "virustotal")
    assert ok is False
    assert "provider" in reason.lower()


def test_api_template_allows_known_provider_correct_host():
    ok, _ = validate_api_template("https://www.virustotal.com/api/v3/files/{value}", "virustotal")
    assert ok is True


# ── header hardening ───────────────────────────────────────────────────────


def test_build_headers_strips_host_override():
    headers = _build_headers('{"Host": "internal.local", "X-Api-Key": "{token}", "Content-Length": "0"}', "sekret")
    assert "Host" not in headers and "host" not in {k.lower() for k in headers}
    assert "content-length" not in {k.lower() for k in headers}
    assert headers["X-Api-Key"] == "sekret"


# ── ENRICHMENT_REQUIRE_PUBLIC_HOST ─────────────────────────────────────────
#
# The escape hatch for a self-hosted MISP/OpenCTI, or a local stub. It defaults to **on**,
# the opposite of WEBHOOK_REQUIRE_PUBLIC_HOST and AI_REQUIRE_PUBLIC_HOST, because a
# threat-intel API lives on the public internet by definition — so a private address here
# is a misconfiguration or an SSRF attempt, where for those two it is the normal case.


def test_the_guard_is_strict_by_default():
    """The default must not change silently: the whole posture of the feature rests on it."""
    from app.config import settings

    assert settings.enrichment_require_public_host is True


def test_relaxing_it_admits_private_addresses():
    assert _ip_is_blocked("127.0.0.1", require_public=False) is False
    assert _ip_is_blocked("10.0.0.1", require_public=False) is False
    assert _ip_is_blocked("192.168.1.1", require_public=False) is False
    assert _ip_is_blocked("::1", require_public=False) is False


def test_metadata_addresses_are_never_admitted():
    """The one target the switch deliberately does not relax. There is no legitimate
    enrichment endpoint on a metadata address, and reaching it at all is the whole attack."""
    for addr in ("169.254.169.254", "fd00:ec2::254"):
        assert _ip_is_blocked(addr, require_public=False) is True, addr

    ok, reason = validate_enrichment_url("http://169.254.169.254/latest/meta-data/", require_public=False)
    assert ok is False
    assert "169.254.169.254" in reason


def test_a_relaxed_lookup_still_pins_the_connection():
    """Relaxing the range check must not relax rebind protection — the caller still connects
    to the address that was validated, not to whatever the name resolves to next."""
    ok, _reason, pinned = resolve_and_validate_url("http://intel.internal/lookup/x", resolver=_resolver("10.1.2.3"), require_public=False)
    assert ok is True
    assert pinned == "10.1.2.3"


def test_relaxing_does_not_bypass_the_provider_allowlist():
    """`provider_key` still pins the four known providers to their real domains, so a
    relaxed deployment cannot quietly point "virustotal" at something internal."""
    ok, reason = validate_enrichment_url("http://intel.internal/x", allowed_hosts=["virustotal.com"], resolver=_resolver("10.1.2.3"), require_public=False)
    assert ok is False
    assert "allowlist" in reason


def test_a_non_http_scheme_is_still_refused_when_relaxed():
    ok, reason = validate_enrichment_url("file:///etc/passwd", require_public=False)
    assert ok is False
    assert "scheme" in reason


def test_a_relaxed_guard_lets_a_private_ip_template_be_saved(monkeypatch):
    """ENRICHMENT_REQUIRE_PUBLIC_HOST=false is documented as the way to reach a self-hosted
    MISP at `http://10.0.0.5`. The request path honoured it; the save-time check did not, so
    the only way to configure it was a hostname that happened to resolve privately."""
    from app.config import settings
    from app.intel.live_enrichment import validate_api_template

    monkeypatch.setattr(settings, "enrichment_require_public_host", False)
    assert validate_api_template("http://10.0.0.5/attributes/restSearch?value={value}", None) == (True, "ok")
    ok, _ = validate_api_template("http://169.254.169.254/latest/meta-data/{value}", None)
    assert ok is False, "the metadata address stays refused either way"


def test_the_strict_guard_still_refuses_a_private_ip_template(monkeypatch):
    from app.config import settings
    from app.intel.live_enrichment import validate_api_template

    monkeypatch.setattr(settings, "enrichment_require_public_host", True)
    assert validate_api_template("http://10.0.0.5/x/{value}", None)[0] is False
