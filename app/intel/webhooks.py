"""Watch-rule webhook delivery.

Pure module: no FastAPI, no DB, no Huey. `httpx` is imported lazily inside `send()`, the
same shape as `live_enrichment`, so importing this costs nothing.

**Security posture — an explicit, informed trade-off.** Users enter their own webhook URL
and private/internal hosts are permitted by default, because a self-hosted SOC deployment
almost always posts to an internal Mattermost / n8n / SIEM on RFC1918. That does hand every
member a blind-SSRF primitive against the host network. The mitigations here are the ones
that do not cost that flexibility:

  * member-or-above only (enforced at the route);
  * `follow_redirects=False`, so a 302 cannot walk the request somewhere else;
  * the response body is never read, stored, logged or surfaced;
  * a total HTTP deadline across validated addresses and a per-rule rate limit;
  * `169.254.169.254` is blocked unconditionally — the cloud metadata address is the one
    target with no legitimate receiver and catastrophic downside;
  * `WEBHOOK_REQUIRE_PUBLIC_HOST=true` restores the strict `live_enrichment` behaviour
    (public IPs only, DNS-rebinding-safe pinning) for deployments with untrusted members.

The shared secret is never logged and never written to `WebhookDelivery.error_message`.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

from app.json_utils import dumps as _json_dumps
from app.json_utils import loads as _json_loads
from app.network.url_pinning import pin_url_to_ip

__all__ = [
    "BLOCKED_HOSTS",
    "UNSAFE_HEADER_KEYS",
    "WEBHOOK_HEADERS_MAX",
    "WEBHOOK_METHODS",
    "WebhookError",
    "build_job_watch_payload",
    "build_payload",
    "clean_webhook_headers",
    "delivery_headers",
    "pin_url_to_ip",
    "send",
    "sign",
    "validate_url",
    "validate_url_addresses",
    "validate_url_syntax",
]


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


# The cloud metadata endpoint. No real receiver lives here and reaching it from a worker
# yields instance credentials, so it stays blocked regardless of the public-host setting.
BLOCKED_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal", "fd00:ec2::254"})

# The same addresses parsed, for comparing against *resolved* IPs. Matching on the string
# form is not enough there: `fd00:ec2::254` also spells as `fd00:ec2:0:0:0:0:0:254`, and
# `ipaddress` normalises both to one object. The set is derived from BLOCKED_HOSTS rather
# than written out again, so adding an address in one place cannot miss the other.
_BLOCKED_IPS = frozenset(ipaddress.ip_address(h) for h in BLOCKED_HOSTS if _looks_like_ip(h))

WEBHOOK_MAX_ENTITIES = 50  # payload cap; the full count is still reported
_UA = "LogsTotal-Webhook/1"

#: The verbs a rule's webhook may use. Read by the rule form, the YAML import and the seed
#: through one validator (`rules_yaml.validate_spec`), and by the form's `<select>`.
WEBHOOK_METHODS = ("POST", "PUT", "PATCH")
WEBHOOK_HEADERS_MAX = 2000

# Headers a user must not be able to set on an outbound request: Host would break the
# SSRF IP-pinning (the request would be routed to a different vhost than the one
# validated), and the framing headers are managed by httpx — `transfer-encoding` and
# `connection` together are the classic request-smuggling pair.
#
# One constant for every request the server makes on a user's behalf: the webhook editor
# and the enrichment service editor. Two lists would drift, and a rule owner is a *member*,
# not an admin. It lives here rather than in `live_enrichment`, which re-exports it,
# because that module imports this one.
UNSAFE_HEADER_KEYS = frozenset({"host", "content-length", "transfer-encoding", "connection", "expect", "upgrade"})

_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")


def clean_webhook_headers(raw: str | None) -> str | None:
    """Validate a rule's extra-headers JSON. Returns the canonical string, or raises `WebhookError`.

    Header *names* are constrained to token characters and values must be scalars, because
    a newline in either would let a rule owner inject arbitrary headers — or a second
    request — into the outbound call. Content-Type is refused as well: `delivery_headers`
    forces it, so accepting it here would only be a lie.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    if len(raw) > WEBHOOK_HEADERS_MAX:
        raise WebhookError(f"Headers JSON too long (max {WEBHOOK_HEADERS_MAX} chars)")
    try:
        parsed = _json_loads(raw)
    except Exception as exc:
        raise WebhookError("Headers must be a JSON object") from exc
    if not isinstance(parsed, dict):
        raise WebhookError("Headers must be a JSON object")
    clean: dict[str, str] = {}
    for key, value in parsed.items():
        name = str(key).strip()
        if not name or not _HEADER_NAME_RE.fullmatch(name):
            raise WebhookError(f"Invalid header name: {name[:40]!r}")
        if name.lower() in UNSAFE_HEADER_KEYS or name.lower() == "content-type":
            raise WebhookError(f"'{name}' is set by LogsTotal and cannot be overridden")
        if isinstance(value, bool) or value is None or isinstance(value, (list, dict)):
            raise WebhookError(f"Header {name!r} must be a string or number")
        text = str(value)
        if "\n" in text or "\r" in text:
            raise WebhookError(f"Header {name!r} must not contain newlines")
        clean[name] = text
    return _json_dumps(clean) if clean else None


class WebhookError(Exception):
    """Delivery refused before any request was made."""


def build_payload(rule: Any, job: Any, entities: list[Any], *, total: int | None = None) -> dict:
    """One payload per (rule, job) carrying every matched entity.

    Deliberately not one POST per entity: a 500-entity job would otherwise fire 500
    webhooks and look exactly like an outbound flood.
    """
    shown = entities[:WEBHOOK_MAX_ENTITIES]
    return {
        "event": "rule.match",
        "rule": {"id": rule.id, "name": rule.name, "query": rule.query or "", "tag": rule.action_tag},
        "job": {
            "id": getattr(job, "id", None),
            "status": getattr(getattr(job, "status", None), "value", None),
            "score_ratio": getattr(job, "score_ratio", None),
        },
        "match_count": total if total is not None else len(entities),
        "truncated": (total if total is not None else len(entities)) > len(shown),
        "entities": [{"id": e.id, "value": e.value, "type": e.entity_type} for e in shown],
    }


def build_job_rule_payload(rule: Any, job: Any) -> dict:
    """One payload for a `scope="job"` rule that matched the job itself.

    The third `event` value, and shaped as a sibling of the other two for the same reason
    `job.watch` is: **`entities` is present and empty on purpose**. A receiver written
    against `rule.match` very likely indexes `payload["entities"]`, and a KeyError there
    would turn a new feature into an outage in somebody else's script.

    `match_count` is always 1. A job rule is a single-row test — it matched or it did not —
    so there is nothing to truncate and `truncated` is always False. Both keys are kept
    rather than dropped, so a receiver can read every payload the same way.

    The job block carries a little more than the other two: a job rule is *about* the job,
    so the fields its criteria are written against are the ones worth sending.
    """
    return {
        "event": "job.match",
        "rule": {"id": rule.id, "name": rule.name, "query": rule.query or "", "tag": rule.action_tag},
        "job": {
            "id": getattr(job, "id", None),
            "status": getattr(getattr(job, "status", None), "value", None),
            "score_ratio": getattr(job, "score_ratio", None),
            "total_findings": getattr(job, "total_findings", None),
            "severity_summary": getattr(job, "severity_summary", None),
        },
        "match_count": 1,
        "truncated": False,
        "entities": [],
    }


def build_job_watch_payload(rule: Any, job: Any, events: list[Any], *, total: int | None = None) -> dict:
    """One payload per (rule, job) carrying the job-watch events that just landed.

    Shaped as a sibling of `build_payload`, not a different message: `event` is the
    discriminator, and **`entities` is present and empty on purpose**. A receiver written
    against `rule.match` very likely indexes `payload["entities"]`, and a KeyError there
    would turn a new feature into an outage in somebody else's script.
    """
    shown = events[:WEBHOOK_MAX_ENTITIES]
    count = total if total is not None else len(events)
    return {
        "event": "job.watch",
        "rule": {"id": rule.id, "name": rule.name},
        "job": {
            "id": getattr(job, "id", None),
            "status": getattr(getattr(job, "status", None), "value", None),
            "score_ratio": getattr(job, "score_ratio", None),
        },
        "match_count": count,
        "truncated": count > len(shown),
        "entities": [],
        "events": [
            {
                "kind": e.kind,
                "ref_id": e.ref_id,
                "summary": e.summary or "",
                "at": (e.created_at.isoformat() + "Z") if getattr(e, "created_at", None) else None,
            }
            for e in shown
        ],
    }


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """`sha256=<hex>` over `timestamp.body`.

    The timestamp is inside the signed material so a captured delivery cannot be replayed
    indefinitely — a receiver that checks freshness has something to check against.
    """
    mac = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode() + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def validate_url_syntax(url: str) -> None:
    """The DNS-free checks: scheme, host present, no credentials, not a metadata address.

    Split out from `validate_url` so *saving* a rule does not depend on the receiver being
    resolvable at that moment — a webhook host can be legitimately down, or only resolvable
    from the worker's network, and refusing to save the rule for that would be wrong. The
    resolution check happens at delivery time, which is the only moment it protects
    anything anyway (and is rebinding-safe there, unlike a check at save time).
    """
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https"):
        raise WebhookError("URL must start with http:// or https://")
    if not parsed.hostname:
        raise WebhookError("URL has no host")
    if parsed.username or parsed.password:
        # Credentials in the URL would end up in logs and error strings.
        raise WebhookError("URL must not embed credentials")
    try:
        parsed.port  # noqa: B018 — urlparse validates the port lazily, and raises ValueError
    except ValueError as exc:
        raise WebhookError(f"URL has an invalid port: {exc}") from None
    if parsed.hostname.lower() in BLOCKED_HOSTS:
        raise WebhookError("that host is not allowed")
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    if literal is not None and _unwrap_ipv4_mapped(literal) in _BLOCKED_IPS:
        raise WebhookError("that host is not allowed")


def _unwrap_ipv4_mapped(ip):
    """`::ffff:a.b.c.d` as the IPv4 address it reaches.

    A dual-stack socket connecting to an IPv4-mapped address talks to the IPv4 host, and an
    `IPv6Address` never compares equal to an `IPv4Address` — so without this the metadata
    block had a spelling that walked straight past it. `live_enrichment._ip_is_blocked`
    unwraps the same way.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def validate_url_addresses(url: str, *, require_public: bool = False, public_setting_name: str = "WEBHOOK_REQUIRE_PUBLIC_HOST") -> list[str]:
    """Validate, and return **every** address the request may be pinned to, in resolution order.

    Everything `validate_url_syntax` checks, plus DNS: with `require_public`, every resolved
    IP must be global — the same rule `live_enrichment` applies to admin-configured lookups.
    Call this immediately before the request, never at save time.

    `public_setting_name` only names the env var in the refusal message. It exists because
    `app/ai/client.py` shares this guard under a different switch, and an error telling an
    admin to look at a setting they did not set is a wrong error.

    Returning the addresses is what makes the check binding. Handing the *hostname* back to
    httpx would resolve it a second time, and a short-TTL record answering publicly here and
    internally there would walk straight through — with DB round trips between the two
    lookups to widen the window. Callers connect to one of these addresses with the original
    Host header and TLS SNI, so there is no second lookup to poison: the
    "DNS-rebinding-safe pinning" this module's docstring promises.

    **Every address is checked, so every address returned is equally safe** — which is what
    lets a caller fall through the list on a connection error. `getaddrinfo` order is
    preserved (deduplicated, not set-ified) because it is the system's own preference
    order: `localhost` resolves to both `::1` and `127.0.0.1`, and with a set a receiver
    listening on IPv4 only — an Ollama, or any number of internal webhook targets — would be
    reachable or not depending on hash ordering.
    """
    validate_url_syntax(url)
    host = urlparse(url or "").hostname or ""

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise WebhookError(f"could not resolve host: {exc}") from exc

    chosen: list[str] = []
    for addr in dict.fromkeys(info[4][0] for info in infos):
        try:
            ip = _unwrap_ipv4_mapped(ipaddress.ip_address(addr))
        except ValueError:
            continue
        # Not `ip.is_link_local and ...`: fd00:ec2::254 is unique-local, not link-local,
        # so that conjunct would block the EC2 IPv6 metadata address only when written as
        # a URL literal, never when reached through a hostname.
        if ip in _BLOCKED_IPS:
            raise WebhookError("that host is not allowed")
        if require_public and not ip.is_global:
            raise WebhookError(f"{public_setting_name} is set and this host resolves to a private address")
        chosen.append(addr)

    if not chosen:
        raise WebhookError("could not resolve host to a usable address")
    return chosen


def validate_url(url: str, *, require_public: bool = False, public_setting_name: str = "WEBHOOK_REQUIRE_PUBLIC_HOST") -> str:
    """Single-address form of :func:`validate_url_addresses` — the first, preferred address.

    The webhook delivery path's entry point.
    """
    return validate_url_addresses(url, require_public=require_public, public_setting_name=public_setting_name)[0]


def send(url: str, body: bytes, headers: dict[str, str], *, timeout: float = 5.0, method: str = "POST", pin_ip: str | None = None) -> tuple[int | None, str | None]:
    """Synchronous worker entry point; cancel all HTTP I/O at the total deadline.

    A validated pinned IP is required by the delivery worker. Response bodies are
    never read, returned or logged. Closing the streaming context releases the socket.
    """
    import asyncio

    return asyncio.run(_send_async(url, body, headers, timeout=timeout, method=method, pin_ip=pin_ip))


async def _send_async(url: str, body: bytes, headers: dict[str, str], *, timeout: float, method: str, pin_ip: str | None) -> tuple[int | None, str | None]:
    import asyncio

    import httpx

    if timeout <= 0:
        return None, "timed out"
    connect_url = url
    extensions = None
    if pin_ip:
        connect_url, host_header = pin_url_to_ip(url, pin_ip)
        headers = {**headers, "Host": host_header}
        if urlparse(url).scheme == "https":
            extensions = {"sni_hostname": urlparse(url).hostname}
    try:
        async with (
            asyncio.timeout(timeout),
            httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client,
            client.stream(method, connect_url, content=body, headers=headers, extensions=extensions) as resp,
        ):
            return resp.status_code, None
    except (TimeoutError, httpx.TimeoutException):
        return None, "timed out"
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {exc}"[:280]


def delivery_headers(delivery_id: int, timestamp: str, signature: str | None, extra: dict | None = None, *, event: str = "rule.match") -> dict[str, str]:
    """Our headers always win: `extra` is applied first, so a rule owner cannot spoof the
    signature, the timestamp or the event type by naming them in their custom headers.

    `event` defaults to `rule.match`; it exists because a rule's webhook can also carry
    `job.watch` deliveries, and a receiver
    routing on the header must not be told they are the same thing.
    """
    headers: dict[str, str] = {}
    for k, v in (extra or {}).items():
        headers[str(k)] = str(v)
    headers.update(
        {
            "Content-Type": "application/json",
            "User-Agent": _UA,
            "X-LogsTotal-Event": event,
            "X-LogsTotal-Delivery": str(delivery_id),
            "X-LogsTotal-Timestamp": timestamp,
        }
    )
    if signature:
        headers["X-LogsTotal-Signature"] = signature
    return headers
