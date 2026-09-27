"""Client IP resolution helpers for routes and ASGI middleware."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from fastapi import Request
from starlette.types import Scope

from app.config import settings

_FORWARDED_FOR_RE = re.compile(r'for=(?:"?\[?)([^;\],"]+)')


def get_client_ip(request: Request) -> str | None:
    """Resolve client IP from a FastAPI request."""
    return get_client_ip_from_scope(request.scope)


def get_client_ip_from_scope(scope: Scope) -> str | None:
    """Resolve client IP from ASGI scope with optional trusted-proxy headers."""
    peer_ip = _scope_peer_ip(scope)
    if not settings.trust_proxy_headers:
        return peer_ip

    if not _is_trusted_proxy(peer_ip):
        return peer_ip

    headers = _scope_headers(scope)
    for candidate in _forwarded_candidates(headers):
        normalized = _normalize_ip(candidate)
        if normalized:
            return normalized
    return peer_ip


def _scope_peer_ip(scope: Scope) -> str | None:
    client = scope.get("client")
    if not client:
        return None
    return _normalize_ip(str(client[0]))


def _scope_headers(scope: Scope) -> dict[str, str]:
    raw_headers = scope.get("headers", [])
    out: dict[str, str] = {}
    for key, value in raw_headers:
        try:
            out[key.decode("latin-1").lower()] = value.decode("latin-1")
        except Exception:
            continue
    return out


def _forwarded_candidates(headers: dict[str, str]) -> Iterable[str]:
    """Forwarded-header candidates, most-trustworthy first.

    Proxy chains are built by **appending**: each hop adds the address it saw to the right
    of whatever arrived. So in ``X-Forwarded-For: <a>, <b>, <c>``, ``c`` was written by the
    proxy we are talking to and ``a`` is whatever the original client chose to send. Reading
    left-to-right hands the value straight to the client.

    That is not theoretical here: the bundled Caddy is a bare ``reverse_proxy web:8000``
    with no ``trusted_proxies``, so it appends rather than replaces, and the documented
    production config turns ``TRUST_PROXY_HEADERS`` on. Left-to-right, any caller could pick
    their own IP, and every per-IP bucket — login, upload, resubmit — would be a fresh bucket
    per forged value, i.e. no rate limit at all.

    Walking right-to-left and skipping our own proxies yields the closest hop we did not
    write ourselves, which is the real client for one proxy and stays correct for several.
    """
    xff = headers.get("x-forwarded-for", "")
    if xff:
        yield from _rightmost_untrusted(part.strip() for part in xff.split(","))

    forwarded = headers.get("forwarded", "")
    if forwarded:
        yield from _rightmost_untrusted(m.group(1).strip() for m in _FORWARDED_FOR_RE.finditer(forwarded))

    # A single value written by the proxy itself — there is no chain to mis-read.
    x_real_ip = headers.get("x-real-ip", "").strip()
    if x_real_ip:
        yield x_real_ip


def _rightmost_untrusted(parts: Iterable[str]) -> Iterable[str]:
    """Yield chain entries from the right, our own proxies last.

    Trusted hops are not dropped, only deprioritised: a chain consisting entirely of
    trusted addresses (an internal probe through the proxy) should still resolve to one of
    them rather than falling through to the peer.
    """
    entries = [p for p in parts if p]
    trusted: list[str] = []
    for part in reversed(entries):
        normalized = _normalize_ip(part)
        if normalized and _is_trusted_proxy(normalized):
            trusted.append(part)
            continue
        yield part
    # Every hop was ours, so the chain is internal end to end and its leftmost entry — the
    # origin, as reported by a proxy we do trust — is the most useful answer. Undo the
    # right-to-left walk for these.
    yield from reversed(trusted)


def _is_trusted_proxy(peer_ip: str | None) -> bool:
    if not peer_ip:
        return False
    raw = settings.trusted_proxy_cidrs.strip()
    if raw == "*":
        return True
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError:
            continue
        if ip in net:
            return True
    return False


def _normalize_ip(value: str) -> str | None:
    v = value.strip().strip('"')
    if not v:
        return None

    # RFC 7239 / IPv6 literals can include brackets and optional port.
    if v.startswith("[") and "]" in v:
        v = v[1 : v.index("]")]
    elif v.count(":") == 1 and "." in v:
        # Likely IPv4:port
        host, _, maybe_port = v.rpartition(":")
        if host and maybe_port.isdigit():
            v = host

    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None
