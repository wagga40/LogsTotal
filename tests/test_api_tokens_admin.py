"""The API tokens page warns when the instance sits behind HTTP basic auth.

A request carries one Authorization header, and a basic-auth proxy takes it for its own
password, so a token client cannot get through. The page knows the proxy is there because
the admin's own browser sends `Authorization: Basic …` to reach it.
"""

from __future__ import annotations

_BASIC = {"Authorization": "Basic dXNlcjpwYXNz"}
_NOTICE = 'id="basic-auth-token-notice"'


async def test_the_page_warns_behind_basic_auth(admin_client):
    body = (await admin_client.get("/admin/api-tokens", headers=_BASIC)).text
    assert _NOTICE in body
    assert "behind HTTP basic auth" in body


async def test_the_page_says_nothing_without_basic_auth(admin_client):
    body = (await admin_client.get("/admin/api-tokens")).text
    assert _NOTICE not in body


async def test_the_new_token_page_warns_too(admin_client):
    """The plaintext page is a second render of the same template, with its own context."""
    resp = await admin_client.post(
        "/admin/api-tokens",
        data={"name": "SIEM", "scopes": ["ioc_feed:read"]},
        headers=_BASIC,
    )
    assert resp.status_code == 200
    assert "Save this token now" in resp.text
    assert _NOTICE in resp.text
