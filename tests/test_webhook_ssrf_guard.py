"""The webhook guard has to bind the request, not just inspect the URL.

`app/intel/webhooks.py` documents an explicit trade-off: members may point a rule at an
internal host, because a self-hosted SOC usually posts to an RFC1918 Mattermost or SIEM.
Two things must hold regardless.

1. `WEBHOOK_REQUIRE_PUBLIC_HOST=true` — the documented hardening for untrusted members —
   must bind the request to the addresses it checked. Resolving the hostname, checking the
   addresses and then handing the *hostname* to httpx, which resolves it again, lets a
   short-TTL record that answers publicly for the check and internally for the request walk
   straight through, with several DB round trips between the two lookups. `validate_url`
   returns the address it approved and `send` connects to that, keeping the real Host header
   and TLS SNI.

2. The cloud metadata addresses are blocked unconditionally. A post-DNS test of
   `ip.is_link_local and str(ip) in BLOCKED_HOSTS` short-circuits for `fd00:ec2::254`, which
   is unique-local, not link-local — so the EC2 IPv6 metadata endpoint would be blocked only
   as a literal in the URL, never when reached through a hostname.
"""

from __future__ import annotations

import pytest

from app.intel import webhooks
from app.intel.webhooks import WebhookError, pin_url_to_ip, validate_url


def _fake_getaddrinfo(mapping):
    """Resolve hostnames from *mapping*; anything else raises like a real NXDOMAIN would."""
    import socket

    def _resolve(host, _port, *_a, **_k):
        if host not in mapping:
            raise socket.gaierror(f"unknown host {host}")
        return [(None, None, None, "", (addr, 0)) for addr in mapping[host]]

    return _resolve


# ── Metadata addresses reached through a hostname ────────────────────────────


@pytest.mark.parametrize("addr", ["169.254.169.254", "fd00:ec2::254"])
def test_metadata_address_is_blocked_however_it_is_reached(monkeypatch, addr):
    monkeypatch.setattr(webhooks.socket, "getaddrinfo", _fake_getaddrinfo({"evil.example": [addr]}))
    with pytest.raises(WebhookError, match="not allowed"):
        validate_url("http://evil.example/hook")


def test_the_ipv6_metadata_address_matches_in_its_expanded_form(monkeypatch):
    """`fd00:ec2:0:0:0:0:0:254` is the same address; a string compare would miss it."""
    monkeypatch.setattr(webhooks.socket, "getaddrinfo", _fake_getaddrinfo({"evil.example": ["fd00:ec2:0:0:0:0:0:254"]}))
    with pytest.raises(WebhookError, match="not allowed"):
        validate_url("http://evil.example/hook")


def test_metadata_address_is_still_blocked_as_a_url_literal():
    """The pre-existing syntax check must keep working — this is belt and braces."""
    with pytest.raises(WebhookError, match="not allowed"):
        validate_url("http://169.254.169.254/latest/meta-data/")


@pytest.mark.parametrize("addr", ["::ffff:169.254.169.254", "::ffff:a9fe:a9fe", "0:0:0:0:0:ffff:a9fe:a9fe"])
def test_an_ipv4_mapped_metadata_address_is_blocked_through_a_hostname(monkeypatch, addr):
    """A dual-stack socket connecting to `::ffff:a.b.c.d` reaches the IPv4 host, and an
    IPv6Address never equals the IPv4Address in the blocklist — so the "unconditional" block
    had a spelling that walked past it."""
    monkeypatch.setattr(webhooks.socket, "getaddrinfo", _fake_getaddrinfo({"evil.example": [addr]}))
    with pytest.raises(WebhookError, match="not allowed"):
        validate_url("http://evil.example/hook")


@pytest.mark.parametrize("url", ["http://[::ffff:169.254.169.254]/latest/api/token", "http://[::ffff:a9fe:a9fe]/"])
def test_an_ipv4_mapped_metadata_literal_is_refused_at_save(url):
    from app.intel.webhooks import validate_url_syntax

    with pytest.raises(WebhookError, match="not allowed"):
        validate_url_syntax(url)


def test_a_port_out_of_range_is_a_refusal_not_an_exception():
    """`urlparse(...).port` raises ValueError past 65535. Unhandled, that was a 500 from the
    rule-list Refresh button, and a URL that saved fine and never worked."""
    from app.intel.webhooks import validate_url_syntax

    with pytest.raises(WebhookError, match="port"):
        validate_url_syntax("http://localhost:99999/feed.txt")


# ── Pinning ──────────────────────────────────────────────────────────────────


def test_validate_url_returns_the_address_to_pin_to(monkeypatch):
    monkeypatch.setattr(webhooks.socket, "getaddrinfo", _fake_getaddrinfo({"hooks.example": ["203.0.113.7"]}))
    assert validate_url("https://hooks.example/x") == "203.0.113.7"


def test_private_host_is_allowed_by_default_and_still_pinned(monkeypatch):
    """The permissive default is deliberate; pinning is what keeps it honest."""
    monkeypatch.setattr(webhooks.socket, "getaddrinfo", _fake_getaddrinfo({"mattermost.internal": ["10.1.2.3"]}))
    assert validate_url("http://mattermost.internal/hooks/abc") == "10.1.2.3"


def test_require_public_rejects_a_private_answer(monkeypatch):
    monkeypatch.setattr(webhooks.socket, "getaddrinfo", _fake_getaddrinfo({"rebind.example": ["127.0.0.1"]}))
    with pytest.raises(WebhookError, match="WEBHOOK_REQUIRE_PUBLIC_HOST"):
        validate_url("http://rebind.example/hook", require_public=True)


def test_require_public_rejects_a_host_that_answers_with_both(monkeypatch):
    """Every address must pass, not merely the first — that is the rebinding shape."""
    monkeypatch.setattr(webhooks.socket, "getaddrinfo", _fake_getaddrinfo({"rebind.example": ["203.0.113.7", "127.0.0.1"]}))
    with pytest.raises(WebhookError, match="WEBHOOK_REQUIRE_PUBLIC_HOST"):
        validate_url("http://rebind.example/hook", require_public=True)


@pytest.mark.parametrize(
    ("url", "ip", "expected_url", "expected_host"),
    [
        ("https://hooks.example/x", "203.0.113.7", "https://203.0.113.7/x", "hooks.example"),
        ("http://hooks.example:8080/x?a=1", "203.0.113.7", "http://203.0.113.7:8080/x?a=1", "hooks.example:8080"),
        ("https://hooks.example/x", "2001:db8::1", "https://[2001:db8::1]/x", "hooks.example"),
    ],
)
def test_pinning_preserves_port_path_query_and_host(url, ip, expected_url, expected_host):
    connect, host_header = pin_url_to_ip(url, ip)
    assert connect == expected_url
    assert host_header == expected_host


def test_send_connects_to_the_pinned_ip_not_the_hostname(monkeypatch):
    """The whole point: no second DNS lookup between the check and the request."""
    seen = {}

    class _Resp:
        status_code = 204

        def iter_bytes(self):
            return iter([b""])

    class _Client:
        def __init__(self, **_kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

        def stream(self, method, url, **kw):
            seen["method"] = method
            seen["url"] = url
            seen["headers"] = kw.get("headers") or {}
            seen["extensions"] = kw.get("extensions")

            class _Ctx:
                async def __aenter__(_s):
                    return _Resp()

                async def __aexit__(_s, *_a):
                    return False

            return _Ctx()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    status, error = webhooks.send("https://hooks.example/x", b"{}", {"Content-Type": "application/json"}, pin_ip="203.0.113.7")

    assert (status, error) == (204, None)
    assert seen["url"] == "https://203.0.113.7/x", "send() re-resolved the hostname instead of using the validated address"
    assert seen["headers"]["Host"] == "hooks.example"
    assert seen["extensions"] == {"sni_hostname": "hooks.example"}, "TLS SNI must keep the real name or certificate verification breaks"
