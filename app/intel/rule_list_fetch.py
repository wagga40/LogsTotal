"""Fetching a rule list's values from a URL.

A list can name a `source_url` and a refresh interval; `refresh_rule_lists_periodic` picks
up the ones that are due. The point is the lists whose upstream moves — dynamic-DNS
providers, paste sites, a TLD list, a team's own inventory — where the alternative is
someone remembering to paste a file in every few weeks, and nobody does.

Sync, and the impure half of the feature: the worker calls it directly, and the "Refresh
now" button reaches it through `run_in_threadpool`. Parsing is `rule_lists.normalize_values`
— the same function the textarea and the file drop go through, so a list means the same
thing however its values arrived.

**Security.** This is the webhook guard, not the enrichment one: enrichment keys on a
per-provider host allowlist, which is the wrong shape for an arbitrary feed URL. A list URL
is admin-only, so it sits at the webhook's trust level, but the default is stricter —
`RULE_LIST_REQUIRE_PUBLIC_HOST` defaults **true**, because unlike a webhook receiver this
is fetched on a schedule with nobody watching, and the reason to point it at an internal
address is much rarer than the reason to point a webhook at one. Metadata addresses are
blocked either way. Redirects are not followed, the connection is pinned to a validated IP
so a rebind cannot slip past afterwards, and the body is capped.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from app.config import settings
from app.intel.rule_lists import MAX_LIST_VALUES, VALUE_MAX, normalize_values
from app.intel.webhooks import WebhookError, validate_url_addresses
from app.network.url_pinning import pin_url_to_ip

_log = logging.getLogger(__name__)

__all__ = ["FetchError", "fetch_list_values", "is_due"]

#: A comment convention every threat feed in the wild uses. Dropped before parsing, so a
#: file with a licence header does not become a list with a licence in it.
_COMMENT_PREFIXES = ("#", ";", "//")


class FetchError(Exception):
    """The fetch did not produce values. The message is written to `last_fetch_error` and
    shown to an admin, so it says what went wrong without quoting the response body."""


def is_due(last_fetched_at, refresh_hours: int, *, now) -> bool:
    """Whether a list bound to a URL should be re-fetched.

    `refresh_hours` of 0 means "only when someone presses Refresh" — the right setting for a
    source that changes rarely, and the only one that costs nothing. Never fetched is always
    due, so binding a URL and waiting is enough to get the first copy.
    """
    if refresh_hours <= 0:
        return False
    if last_fetched_at is None:
        return True
    return (now - last_fetched_at).total_seconds() >= refresh_hours * 3600


def _strip_comments(text: str) -> str:
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT_PREFIXES):
            continue
        kept.append(stripped)
    return "\n".join(kept)


def fetch_list_values(url: str) -> tuple[str, ...]:
    """Fetch *url* and return its values, normalised exactly as the textarea's would be.

    Raises `FetchError` with a message fit to show an admin. Never returns an empty tuple:
    a feed that answers 200 with nothing is a broken feed, and quietly emptying a list every
    rule on the instance tests is worse than leaving yesterday's values in place.
    """
    import httpx

    try:
        addresses = validate_url_addresses(
            url,
            require_public=settings.rule_list_require_public_host,
            public_setting_name="RULE_LIST_REQUIRE_PUBLIC_HOST",
        )
    except WebhookError as exc:
        raise FetchError(str(exc)[:280]) from exc

    parsed = urlparse(url)
    cap = settings.rule_list_fetch_max_bytes
    last_error: str | None = None

    # Every address `validate_url_addresses` returned was checked, so every one is equally
    # safe to try — and trying them all is what makes a host with both an A and an AAAA
    # record work when only one of them is listening. The AI client does the same.
    for ip in addresses:
        connect_url, host_header = pin_url_to_ip(url, ip)
        headers = {"Host": host_header, "User-Agent": "LogsTotal", "Accept": "text/plain, */*"}
        extensions = {"sni_hostname": parsed.hostname} if parsed.scheme == "https" else None
        try:
            with (
                httpx.Client(timeout=settings.rule_list_fetch_timeout_seconds, follow_redirects=False) as client,
                client.stream("GET", connect_url, headers=headers, extensions=extensions) as resp,
            ):
                if resp.status_code >= 400:
                    # Terminal for this URL, not this address: a 404 will 404 on the other
                    # one too, and retrying it only doubles the log line.
                    raise FetchError(f"the feed answered HTTP {resp.status_code}")
                if resp.status_code >= 300:
                    raise FetchError(f"the feed redirected (HTTP {resp.status_code}); redirects are not followed")
                chunks: list[bytes] = []
                read = 0
                truncated = False
                for chunk in resp.iter_bytes():
                    read += len(chunk)
                    if read > cap:
                        truncated = True
                        break
                    chunks.append(chunk)
                if truncated:
                    raise FetchError(f"the feed is larger than {cap // 1024} KB")
                body = b"".join(chunks)
        except FetchError:
            raise
        except httpx.TimeoutException:
            last_error = "timed out"
            continue
        except httpx.HTTPError as exc:
            last_error = f"{type(exc).__name__}: {exc}"[:280]
            continue

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FetchError("the feed is not UTF-8 text") from exc

        values = normalize_values(_strip_comments(text))
        values = tuple(v for v in values if len(v) <= VALUE_MAX)
        if not values:
            raise FetchError("the feed returned no usable values")
        if len(values) > MAX_LIST_VALUES:
            raise FetchError(f"the feed returned {len(values)} values; a list holds at most {MAX_LIST_VALUES}")
        return values

    raise FetchError(last_error or "the feed could not be reached")
