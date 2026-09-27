"""Webhook payload, signing and URL policy.

The URL policy here encodes a decision that was made explicitly: users enter their own
webhook URL and **private/internal hosts are allowed by default**, because a self-hosted
deployment posts to an internal Mattermost / n8n / SIEM. `test_private_host_is_allowed_by_default`
pins that on purpose — it is the behaviour someone "hardening" this would break first, and
breaking it makes the feature unusable for its actual audience.

`WEBHOOK_REQUIRE_PUBLIC_HOST=true` is the escape hatch for deployments with untrusted
members, and the metadata address is refused either way.
"""

from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace

import pytest

from app.intel.webhooks import (
    WEBHOOK_MAX_ENTITIES,
    WebhookError,
    build_payload,
    delivery_headers,
    sign,
    validate_url,
)


def _entity(i):
    return SimpleNamespace(id=i, value=f"host{i}.test", entity_type="domain")


def _rule():
    return SimpleNamespace(id=7, name="New LOLBins", query="label:lolbin", action_tag="auto")


def _job():
    return SimpleNamespace(id=42, status=SimpleNamespace(value="completed"), score_ratio="3/10")


class TestPayload:
    def test_shape(self):
        p = build_payload(_rule(), _job(), [_entity(1), _entity(2)])
        assert p["event"] == "rule.match"
        assert p["rule"]["id"] == 7 and p["rule"]["name"] == "New LOLBins"
        assert p["job"]["id"] == 42
        assert p["match_count"] == 2
        assert p["truncated"] is False
        assert [e["value"] for e in p["entities"]] == ["host1.test", "host2.test"]

    def test_entities_are_capped_but_the_true_count_is_reported(self):
        """A 500-entity job must not become a 500-entity body — or 500 POSTs."""
        many = [_entity(i) for i in range(WEBHOOK_MAX_ENTITIES + 25)]
        p = build_payload(_rule(), _job(), many)
        assert len(p["entities"]) == WEBHOOK_MAX_ENTITIES
        assert p["match_count"] == WEBHOOK_MAX_ENTITIES + 25
        assert p["truncated"] is True

    def test_total_override_is_used_for_the_count(self):
        p = build_payload(_rule(), _job(), [_entity(1)], total=9)
        assert p["match_count"] == 9 and p["truncated"] is True

    def test_payload_carries_no_secret_material(self):
        p = build_payload(_rule(), _job(), [_entity(1)])
        assert "secret" not in repr(p).lower()


class TestSigning:
    def test_matches_a_hand_computed_hmac(self):
        body = b'{"a":1}'
        expected = "sha256=" + hmac.new(b"s3cr3t", b"1700000000." + body, hashlib.sha256).hexdigest()
        assert sign("s3cr3t", "1700000000", body) == expected

    def test_timestamp_is_inside_the_signed_material(self):
        """Otherwise a captured delivery replays forever — a receiver has nothing to check."""
        body = b"x"
        assert sign("k", "1", body) != sign("k", "2", body)

    def test_different_secrets_differ(self):
        assert sign("a", "1", b"x") != sign("b", "1", b"x")

    def test_headers_omit_the_signature_when_unsigned(self):
        assert "X-LogsTotal-Signature" not in delivery_headers(1, "123", None)
        assert delivery_headers(1, "123", "sha256=ab")["X-LogsTotal-Signature"] == "sha256=ab"

    def test_headers_carry_delivery_and_timestamp(self):
        h = delivery_headers(9, "1700000000", None)
        assert h["X-LogsTotal-Delivery"] == "9"
        assert h["X-LogsTotal-Timestamp"] == "1700000000"
        assert h["X-LogsTotal-Event"] == "rule.match"


class TestUrlPolicy:
    @pytest.mark.parametrize("url", ["ftp://x.test/h", "file:///etc/passwd", "javascript:alert(1)", "", "http://"])
    def test_bad_schemes_and_missing_hosts_are_refused(self, url):
        with pytest.raises(WebhookError):
            validate_url(url)

    def test_embedded_credentials_are_refused(self):
        """They would end up in logs and error strings."""
        with pytest.raises(WebhookError, match="credentials"):
            validate_url("https://user:pw@example.com/hook")

    def test_metadata_address_is_always_refused(self):
        """No legitimate receiver lives there and it yields instance credentials."""
        with pytest.raises(WebhookError):
            validate_url("http://169.254.169.254/latest/meta-data/")
        with pytest.raises(WebhookError):
            validate_url("http://169.254.169.254/x", require_public=True)

    def test_private_host_is_allowed_by_default(self):
        """The accepted trade-off. Self-hosted receivers live on RFC1918 — do not "fix" this."""
        validate_url("http://127.0.0.1:8080/hook")

    def test_private_host_is_refused_when_public_is_required(self):
        with pytest.raises(WebhookError, match="WEBHOOK_REQUIRE_PUBLIC_HOST"):
            validate_url("http://127.0.0.1:8080/hook", require_public=True)

    def test_unresolvable_host_is_refused(self):
        with pytest.raises(WebhookError, match="resolve"):
            validate_url("https://no-such-host.invalid/hook")


class TestSend:
    def test_response_body_is_never_returned(self, monkeypatch):
        """The body is dropped on the floor, which is what stops delivery being a read primitive."""
        import app.intel.webhooks as wh

        captured = {}

        class _Resp:
            status_code = 200

            def iter_bytes(self):
                captured["read"] = True
                yield b"internal secret data"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class _Client:
            def __init__(self, **kw):
                captured["kwargs"] = kw

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            def stream(self, *a, **kw):
                return _Resp()

        monkeypatch.setitem(
            __import__("sys").modules, "httpx", SimpleNamespace(AsyncClient=_Client, TimeoutException=type("T", (Exception,), {}), HTTPError=type("H", (Exception,), {}))
        )
        status, error = wh.send("https://example.test/h", b"{}", {})
        assert (status, error) == (200, None)
        assert "read" not in captured
        assert captured["kwargs"]["follow_redirects"] is False, "a redirect could walk the request elsewhere"


class TestValidationSplit:
    """Saving a rule must not depend on the receiver resolving right at that moment.

    A webhook host can be legitimately down, or resolvable only from the worker's network.
    Refusing to *save* the rule for that is wrong, and a resolution check at save time
    protects nothing anyway — a DNS answer can change between save and send. The split puts
    the DNS check immediately before the request, where it is also rebinding-safe.
    """

    def test_syntax_check_does_not_resolve(self):
        from app.intel.webhooks import validate_url_syntax

        validate_url_syntax("https://a-host-that-does-not-exist.invalid/hook")

    def test_syntax_check_still_refuses_the_obvious(self):
        from app.intel.webhooks import validate_url_syntax

        for bad in ("ftp://x.test/h", "", "http://", "https://u:p@x.test/h", "http://169.254.169.254/x"):
            with pytest.raises(WebhookError):
                validate_url_syntax(bad)

    def test_full_check_still_resolves(self):
        with pytest.raises(WebhookError, match="resolve"):
            validate_url("https://a-host-that-does-not-exist.invalid/hook")
