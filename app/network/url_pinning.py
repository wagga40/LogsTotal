"""Connect-pinning for outbound requests that have already passed an SSRF check.

Both outbound paths — live enrichment (`app/intel/live_enrichment.py`) and watch-rule
webhooks (`app/intel/webhooks.py`) — validate a URL by resolving its host and checking
every address, then make the request. Between those two steps the name can be re-resolved
to something else — a short-TTL DNS record would defeat ``WEBHOOK_REQUIRE_PUBLIC_HOST``
that way. Pinning closes that window: the request connects to the address that was
approved, and nothing looks the name up a second time.

One implementation for both: a security primitive with two copies has two behaviours
eventually.

Pure stdlib, no app imports — both callers are pure modules and must stay that way.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse


def pin_url_to_ip(url: str, ip: str) -> tuple[str, str]:
    """Rewrite *url* to connect to the validated *ip* while preserving the real host.

    Returns ``(connect_url, host_header)``. The connect URL targets the pinned address so
    no second DNS lookup happens; the ``Host`` header keeps the original hostname for
    vhost routing, and the caller passes that same hostname as the TLS SNI so certificate
    verification still checks the real name rather than the IP.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    ip_host = f"[{ip}]" if ":" in ip else ip
    netloc = f"{ip_host}:{port}" if port else ip_host
    host_header = f"{host}:{port}" if port else host
    connect = urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    return connect, host_header
