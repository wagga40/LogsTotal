"""Live (API) enrichment — on-demand outbound lookups against configured services.

Security-critical module. Every outbound URL passes ``resolve_and_validate_url`` before
any request: the scheme must be http(s), the host must (optionally) match a per-provider
allowlist, and every IP the host resolves to must be a routable public address. That last
rule is ``ENRICHMENT_REQUIRE_PUBLIC_HOST`` (default true); an operator may turn it off to
reach a self-hosted MISP/OpenCTI, and cloud-metadata addresses stay blocked either way.
With it on, this blocks SSRF to loopback/RFC1918/link-local addresses as well, including
DNS-rebinding (a public name that resolves to an internal IP) — the connection is then
pinned to the validated address via ``app.network.url_pinning``, so nothing resolves the
name a second time.

The SSRF helpers are dependency-injectable (``resolver``) and free of FastAPI/Huey
imports so they unit-test without the network.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from collections.abc import Callable
from datetime import timedelta
from urllib.parse import quote, urlparse

from app.config import settings
from app.intel.webhooks import _BLOCKED_IPS, UNSAFE_HEADER_KEYS
from app.network.url_pinning import pin_url_to_ip

_log = logging.getLogger(__name__)

# Per-provider host allowlists (suffix match). Custom services (unknown provider_key)
# get no allowlist — the IP-resolution check still defends them against SSRF.
PROVIDER_HOSTS: dict[str, list[str]] = {
    "virustotal": ["virustotal.com"],
    "abuseipdb": ["abuseipdb.com"],
    "shodan": ["shodan.io"],
    "urlscan": ["urlscan.io"],
}

# Cap on stored response body.
MAX_RESPONSE_BYTES = 64 * 1024


# ── SSRF guard ─────────────────────────────────────────────────────────────


def _ip_is_blocked(ip_str: str, *, require_public: bool = True) -> bool:
    """True if this address may not be connected to.

    With ``require_public`` (the default, and what `ENRICHMENT_REQUIRE_PUBLIC_HOST`
    controls) this is ``not is_global`` rather than an exclusion list, so every
    special-purpose range is rejected — including CGNAT ``100.64.0.0/10``, which is neither
    ``is_private`` nor ``is_global``. IPv4-mapped IPv6 (``::ffff:a.b.c.d``) is unwrapped
    first so the embedded IPv4 is classified correctly.

    Without it, private and loopback addresses are allowed so a service can point at a host
    on your own network — but **the metadata addresses stay blocked either way**. Those have
    no legitimate use as an enrichment endpoint and are the one target where reaching them
    at all is the whole attack, so they are not part of what the switch relaxes.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # not an IP → treat as unsafe
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr in _BLOCKED_IPS:
        return True
    if not require_public:
        return False
    return not addr.is_global


def _default_resolver(host: str) -> list[str]:
    """Resolve a hostname to the list of IP strings it maps to."""
    infos = socket.getaddrinfo(host, None)
    return [info[4][0] for info in infos]


def _host_in_allowlist(host: str, allowed: list[str]) -> bool:
    host = host.lower()
    for entry in allowed:
        e = entry.lower().lstrip(".")
        if host == e or host.endswith("." + e):
            return True
    return False


def resolve_and_validate_url(
    url: str,
    *,
    allowed_hosts: list[str] | None = None,
    resolver: Callable[[str], list[str]] | None = None,
    require_public: bool | None = None,
) -> tuple[bool, str, str | None]:
    """Single-address form of :func:`resolve_and_validate_addresses` — the first one."""
    ok, reason, addresses = resolve_and_validate_addresses(url, allowed_hosts=allowed_hosts, resolver=resolver, require_public=require_public)
    return ok, reason, (addresses[0] if addresses else None)


def resolve_and_validate_addresses(
    url: str,
    *,
    allowed_hosts: list[str] | None = None,
    resolver: Callable[[str], list[str]] | None = None,
    require_public: bool | None = None,
) -> tuple[bool, str, list[str]]:
    """Validate an outbound URL for SSRF safety and return every IP it may be pinned to.

    Returns ``(ok, reason, addresses)``. ``ok`` is True only when the scheme is http(s),
    the host is present (and within ``allowed_hosts`` when that list is non-empty), and
    **no** IP the host resolves to is blocked by ``_ip_is_blocked``. ``addresses`` are those
    validated IPs, deduplicated in resolution order; the caller connects to one directly so
    a later DNS re-resolution (rebinding) can't swap in an internal IP after the check, and
    may fall through to the next on a connection error — every one was checked.

    ``require_public`` defaults to the `ENRICHMENT_REQUIRE_PUBLIC_HOST` setting. It is an
    explicit argument as well so the pure guard stays testable without touching settings,
    and so a future caller with a different policy cannot silently inherit this one's.
    """
    if require_public is None:
        require_public = settings.enrichment_require_public_host
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return False, "unparseable URL", []

    if parsed.scheme not in ("http", "https"):
        return False, f"disallowed scheme: {parsed.scheme or '(none)'}", []

    host = parsed.hostname
    if not host:
        return False, "missing host", []

    if allowed_hosts and not _host_in_allowlist(host, allowed_hosts):
        return False, f"host not in allowlist: {host}", []

    # Resolved here, not bound as the parameter's default. A default is evaluated once at
    # import, so `resolver=_default_resolver` would capture the original function object,
    # and monkeypatching the module attribute would do nothing for any caller that does not
    # pass `resolver=` — the enrichment route among them — turning a stubbed test into a
    # live DNS lookup.
    resolver = resolver or _default_resolver

    # If the host is an IP literal, check it directly; otherwise resolve and check all.
    try:
        ipaddress.ip_address(host)
        candidates = [host]
    except ValueError:
        try:
            candidates = resolver(host)
        except OSError as exc:
            return False, f"DNS resolution failed: {exc}", []
        if not candidates:
            return False, "host did not resolve", []

    for ip in candidates:
        if _ip_is_blocked(ip, require_public=require_public):
            return False, f"blocked (non-public) address: {ip}", []

    return True, "ok", list(dict.fromkeys(candidates))


def validate_api_template(template: str | None, provider_key: str | None) -> tuple[bool, str]:
    """Static (no-DNS) SSRF sanity check for an admin-supplied ``api_template``.

    The runtime path still enforces :func:`resolve_and_validate_url`; this catches obvious
    misconfiguration at save time: a non-http(s) scheme, a private/non-public IP literal,
    or a host that doesn't match a known provider's allowlist.
    """
    if not template:
        return True, "ok"
    probe = template.replace("{value}", "x").replace("{token}", "x")
    try:
        parsed = urlparse(probe)
    except (ValueError, TypeError):
        return False, "api_template is not a parseable URL"
    if parsed.scheme not in ("http", "https"):
        return False, f"api_template scheme must be http or https (got {parsed.scheme or '(none)'})"
    host = parsed.hostname
    if not host:
        return False, "api_template is missing a host"
    try:
        ipaddress.ip_address(host)
        # The same policy the request path applies: ENRICHMENT_REQUIRE_PUBLIC_HOST=false is
        # how a self-hosted endpoint on a private address is reached, and refusing its IP
        # literal here left it unconfigurable. Metadata addresses stay refused either way.
        if _ip_is_blocked(host, require_public=settings.enrichment_require_public_host):
            return False, f"api_template points at a non-public address: {host}"
    except ValueError:
        pass
    allowed = PROVIDER_HOSTS.get((provider_key or "").lower())
    if allowed and not _host_in_allowlist(host, allowed):
        return False, f"api_template host {host!r} is not allowed for provider {provider_key!r}"
    return True, "ok"


# ── Provider-aware response summarisers (pure) ─────────────────────────────


def _summarize_virustotal(body: dict) -> dict:
    attrs = body.get("data") or {}
    attrs = attrs.get("attributes") if isinstance(attrs, dict) else None
    if not isinstance(attrs, dict):
        return {}
    stats = attrs.get("last_analysis_stats") if isinstance(attrs.get("last_analysis_stats"), dict) else {}
    out: dict = {}
    if stats:
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values())
        out["detections"] = f"{malicious} / {total}"
        out["malicious"] = malicious
        out["suspicious"] = suspicious
    if isinstance(attrs.get("tags"), list):
        out["tags"] = attrs["tags"][:10]
    if "reputation" in attrs:
        out["reputation"] = attrs.get("reputation")
    return out


def _summarize_abuseipdb(body: dict) -> dict:
    data = body.get("data") if isinstance(body.get("data"), dict) else {}
    out: dict = {}
    if "abuseConfidenceScore" in data:
        out["abuse_score"] = data.get("abuseConfidenceScore")
    if "totalReports" in data:
        out["reports"] = data.get("totalReports")
    if data.get("countryCode"):
        out["country"] = data.get("countryCode")
    if data.get("isp"):
        out["isp"] = data.get("isp")
    return out


def _summarize_shodan(body: dict) -> dict:
    out: dict = {}
    if isinstance(body.get("ports"), list):
        out["open_ports"] = body["ports"]
    if body.get("org"):
        out["org"] = body.get("org")
    if isinstance(body.get("hostnames"), list):
        out["hostnames"] = body["hostnames"][:10]
    if body.get("os"):
        out["os"] = body.get("os")
    return out


def _summarize_urlscan(body: dict) -> dict:
    out: dict = {}
    if "total" in body:
        out["total_results"] = body.get("total")
    results = body.get("results")
    if isinstance(results, list) and results:
        first = results[0]
        task = first.get("task") if isinstance(first, dict) else None
        if isinstance(task, dict) and task.get("url"):
            out["top_url"] = task["url"]
    return out


_SUMMARISERS = {
    "virustotal": _summarize_virustotal,
    "abuseipdb": _summarize_abuseipdb,
    "shodan": _summarize_shodan,
    "urlscan": _summarize_urlscan,
}


def summarize_response(provider_key: str | None, body: dict) -> dict:
    """Extract a small, display-ready dict from a provider's raw JSON response.

    Unknown providers (or anything that doesn't parse) return ``{"raw_available": True}``
    so the UI can still offer the raw body without pretending to understand it.
    """
    fn = _SUMMARISERS.get((provider_key or "").lower())
    if fn is None:
        return {"raw_available": True}
    try:
        summary = fn(body if isinstance(body, dict) else {})
    except (KeyError, TypeError, ValueError):
        return {"raw_available": True}
    return summary or {"raw_available": True}


# ── Derived verdict (pure) ─────────────────────────────────────────────────

# Ordered weakest → strongest. The relationship graph ships the *index* into this tuple and
# never the summary itself, let alone `response_json` or a decrypted token: a verdict is a
# small integer, and that is the whole point — one number cannot carry a provider's raw
# body onto a canvas by accident.
ENRICHMENT_VERDICTS: tuple[str, ...] = ("none", "clean", "unknown", "suspicious", "malicious")

_VERDICT_RANK = {name: i for i, name in enumerate(ENRICHMENT_VERDICTS)}

# Thresholds in one reviewable place rather than scattered through per-provider branches.
_VT_MALICIOUS_STRONG = 4
_ABUSE_MALICIOUS = 50
_ABUSE_SUSPICIOUS = 25


def verdict_from_summary(provider_key: str | None, summary: dict | None) -> int:
    """Map a stored `summary_json` to an `ENRICHMENT_VERDICTS` index.

    Only providers whose response actually expresses a judgement get one. Shodan and
    urlscan return **no verdict**: open ports and a scan count are facts, not opinions, and
    painting a node red because a host answers on 443 would be worse than painting nothing.
    Unknown providers likewise — their summary is `{"raw_available": True}` by construction.

    Never raises; anything unparseable is "none" (index 0).
    """
    if not isinstance(summary, dict):
        return 0
    key = (provider_key or "").lower()
    try:
        if key == "virustotal":
            malicious = int(summary.get("malicious") or 0)
            suspicious = int(summary.get("suspicious") or 0)
            if malicious >= _VT_MALICIOUS_STRONG:
                return _VERDICT_RANK["malicious"]
            if malicious >= 1 or suspicious >= 1:
                return _VERDICT_RANK["suspicious"]
            # A detections string with a zero numerator is a real "nobody flags this",
            # which is worth showing; an absent one means we never got stats at all.
            return _VERDICT_RANK["clean"] if summary.get("detections") else 0
        if key == "abuseipdb":
            if summary.get("abuse_score") is None:
                return 0
            score = int(summary.get("abuse_score") or 0)
            if score >= _ABUSE_MALICIOUS:
                return _VERDICT_RANK["malicious"]
            if score >= _ABUSE_SUSPICIOUS:
                return _VERDICT_RANK["suspicious"]
            return _VERDICT_RANK["clean"]
    except (TypeError, ValueError):
        return 0
    return 0


# ── Fetch orchestration ────────────────────────────────────────────────────


def _fill_template(template: str, value: str, token: str | None) -> str:
    """Substitute {value} (URL-encoded) and {token} without str.format (avoids KeyErrors)."""
    return template.replace("{value}", quote(value, safe="")).replace("{token}", token or "")


# `UNSAFE_HEADER_KEYS` — the headers a user must never set on an outbound request — is
# defined in `app/intel/webhooks.py` (this module imports that one, so it cannot be the
# other way round) and imported above so existing readers keep finding it here. One
# constant, one trust decision, for both editors.


def _build_headers(api_headers_json: str | None, token: str | None) -> dict[str, str]:
    from app.json_utils import loads as _json_loads

    if not api_headers_json:
        return {}
    try:
        raw = _json_loads(api_headers_json)
    except (ValueError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(v, str):
            continue
        if str(k).strip().lower() in UNSAFE_HEADER_KEYS:
            continue
        out[str(k)] = v.replace("{token}", token or "")
    return out


def _rate_limited(service_id: int) -> bool:
    """Per-service fixed-window rate limit via Redis. Fails open if Redis is unavailable."""
    limit = settings.enrichment_rate_limit_per_minute
    if not limit or limit <= 0:
        return False
    try:
        from app.redis_client import get_redis

        r = get_redis()
        key = f"logstotal:enrich:rate:{service_id}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, 60)
        return int(count) > limit
    except Exception:
        return False


async def fetch_enrichment(db, entity, service, *, force: bool = False, resolver: Callable[[str], list[str]] | None = None):
    """Fetch (or return cached) live enrichment for ``entity`` from ``service``.

    Returns a persisted (or transient, on rate-limit) ``EntityEnrichmentResult``. The
    decrypted API token is never logged nor written to ``error_message``. Redirects are
    NOT followed so a redirect to an internal IP cannot bypass the SSRF check.
    """
    import httpx
    from sqlalchemy import select

    from app.auth.api_tokens import decrypt_secret
    from app.database import utc_now_naive
    from app.json_utils import dumps as _json_dumps
    from app.json_utils import loads as _json_loads
    from app.models import EntityEnrichmentResult

    # Naive UTC throughout: `fetched_at`/`expires_at` are TIMESTAMP WITHOUT TIME ZONE, and
    # asyncpg refuses to bind an aware datetime to those.
    now = utc_now_naive()
    ttl = int(getattr(service, "cache_ttl_seconds", 0) or 86400)

    existing = (
        await db.execute(select(EntityEnrichmentResult).where(EntityEnrichmentResult.entity_id == entity.id, EntityEnrichmentResult.service_id == service.id))
    ).scalar_one_or_none()

    # Serve fresh cache unless forced.
    if existing and not force and existing.expires_at and existing.expires_at > now:
        return existing

    # Rate limit — on hit, prefer returning the (possibly stale) cached row.
    if _rate_limited(service.id):
        if existing:
            return existing
        return EntityEnrichmentResult(entity_id=entity.id, service_id=service.id, ok=False, error_message="rate limited — try again shortly", fetched_at=now)

    async def _store(*, ok: bool, error: str | None, response: str | None = None, summary: dict | None = None) -> EntityEnrichmentResult:
        row = existing or EntityEnrichmentResult(entity_id=entity.id, service_id=service.id)
        row.ok = ok
        row.error_message = (error or None) if error else None
        row.response_json = response
        row.summary_json = _json_dumps(summary) if summary else None
        row.fetched_at = now
        row.expires_at = now + timedelta(seconds=ttl)
        if existing is None:
            db.add(row)
        await db.flush()
        return row

    if not service.api_template:
        return await _store(ok=False, error="no API endpoint configured for this service")

    token = decrypt_secret(service.api_token_encrypted) if service.api_token_encrypted else None
    url = _fill_template(service.api_template, entity.value, token)
    allowed = PROVIDER_HOSTS.get((service.provider_key or "").lower())

    ok_url, reason, addresses = resolve_and_validate_addresses(url, allowed_hosts=allowed, resolver=resolver)
    if not ok_url or not addresses:
        # reason never contains the token (it references host/IP only).
        return await _store(ok=False, error=f"blocked by SSRF guard: {reason}")

    method = (service.api_method or "GET").upper()
    extensions = {"sni_hostname": urlparse(url).hostname} if urlparse(url).scheme == "https" else None

    # Streamed and stopped at the cap rather than buffered then measured. `.content`
    # only exists once httpx has read the *whole* body, so a limit checked there is after
    # the fact: a hostile or misconfigured endpoint could return gigabytes and this — which
    # runs inline on the event loop, no Huey hop — would hold all of it in the web process.
    # The 10s timeout does not bound it either, being per-read.
    over_cap = False
    body = bytearray()
    for index, pinned_ip in enumerate(addresses):
        # Pin the connection to a validated IP so a re-resolve can't rebind to an internal
        # address; keep the real Host + TLS SNI for routing/cert checks.
        headers = _build_headers(service.api_headers_json, token)
        connect_url, host_header = pin_url_to_ip(url, pinned_ip)
        headers["Host"] = host_header
        try:
            async with (
                httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client,
                client.stream(method, connect_url, headers=headers, extensions=extensions) as resp,
            ):
                status_code = resp.status_code
                async for chunk in resp.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        over_cap = True
                        break
                encoding = resp.encoding or "utf-8"
            break
        except httpx.ConnectError:
            # Nothing was sent, so the next validated address is safe to try: `localhost`
            # is `::1` and `127.0.0.1`, and a stub listens on one of them.
            if index + 1 < len(addresses):
                continue
            _log.warning("enrichment request failed for service %s: ConnectError", service.name)
            return await _store(ok=False, error="request failed (network error or timeout)")
        except httpx.HTTPError as exc:
            # Do NOT include the URL/exception text — it may carry the token.
            _log.warning("enrichment request failed for service %s: %s", service.name, type(exc).__name__)
            return await _store(ok=False, error="request failed (network error or timeout)")

    if over_cap:
        return await _store(ok=False, error="response too large")

    status_ok = status_code < 400
    text = bytes(body).decode(encoding, errors="replace")
    parsed = None
    try:
        parsed = _json_loads(text)
    except (ValueError, TypeError):
        parsed = None

    summary = summarize_response(service.provider_key, parsed) if (status_ok and isinstance(parsed, dict)) else None
    error = None if status_ok else f"HTTP {status_code}"
    return await _store(ok=status_ok, error=error, response=text, summary=summary)
