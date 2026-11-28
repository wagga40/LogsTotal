"""A failed htmx request is not swapped, so without a toast it is silent.

htmx 4 swaps 4xx/5xx responses by default; base.html's `htmx-config` meta restores htmx 2's
`noSwap` for them, because this app's error answers are not meant to land in a pane.

Without a global handler a lazy-loaded tab keeps its spinner and a rejected form keeps
its stale content, with nothing shown to the user. These pin the toast's wiring, which
route tests cannot reach: the server response is fine, it's the browser that drops it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
APP_JS = (ROOT / "app" / "static" / "app.js").read_text(encoding="utf-8")
BASE_HTML = (ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")


def test_response_and_send_errors_are_both_handled():
    """A 4xx/5xx and a dropped connection are different events; both must surface."""
    assert "htmx:response:error" in APP_JS
    assert "'htmx:error'" in APP_JS, "a network failure produces htmx:error, not response:error"


def test_error_responses_are_not_swapped_into_the_page():
    """htmx 4's default is to swap every response but 204/304; the meta restores htmx 2's."""
    m = re.search(r'<meta name="htmx-config" content=\'([^\']+)\'>', BASE_HTML)
    assert m, "base.html no longer configures htmx"
    import json

    assert json.loads(m.group(1))["noSwap"] == [204, 304, "4xx", "5xx"]
    assert BASE_HTML.index('name="htmx-config"') < BASE_HTML.index("vendor/htmx.min.js"), "htmx reads the meta once, at load"


def test_the_toast_container_exists_in_the_base_layout():
    assert 'id="htmx-error-toast"' in BASE_HTML
    assert "data-toast-message" in BASE_HTML
    assert 'role="alert"' in BASE_HTML, "screen readers need the live region"


def test_toast_classes_are_literal_so_they_survive_a_tailwind_build():
    """`task css:build` scans source for literal class strings — a name assembled at
    runtime renders unstyled in production. Same rule as _tag_chip.html::tag_classes."""
    block = BASE_HTML[BASE_HTML.index('id="htmx-error-toast"') :]
    block = block[: block.index("</div>")]
    assert "{{" not in block, "toast markup must not interpolate class names"
    for literal in ("bg-red-950", "border-red-800", "hidden"):
        assert literal in block


def test_toast_is_not_alpine_driven():
    """It has to work when the failure is what stopped a subtree from initialising."""
    block = BASE_HTML[BASE_HTML.index('id="htmx-error-toast"') :]
    block = block[: block.index("</div>")]
    assert "x-data" not in block
    assert "x-show" not in block


def test_app_js_still_loads_before_alpine():
    """Alpine calls Alpine.start() in a microtask right after its own script, so any
    factory defined in a later deferred script is undefined by then. app.js must be
    loaded before Alpine.start() runs."""
    # Match the <script> tags, not prose: base.html carries a comment naming
    # alpine.min.js above the tags, which a plain substring search finds first.
    tags = re.findall(r'<script[^>]+src="[^"]*/(app\.js|vendor/alpine\.min\.js)[^"]*"', BASE_HTML)
    assert "app.js" in tags and "vendor/alpine.min.js" in tags, tags
    assert tags.index("app.js") < tags.index("vendor/alpine.min.js"), "app.js must load before alpine.min.js"


@pytest.mark.parametrize("status", ["403", "404", "429", "503"])
def test_common_failure_statuses_get_a_specific_message(status):
    handler = APP_JS[APP_JS.index("htmx:response:error") :]
    assert re.search(rf"\b{status}\b", handler[:900]), f"no tailored message for HTTP {status}"


async def test_every_page_carries_the_toast(test_client):
    """It lives in base.html, so any page that can fire an HTMX request has it."""
    for path in ("/", "/jobs", "/docs"):
        resp = await test_client.get(path)
        assert resp.status_code == 200, path
        assert 'id="htmx-error-toast"' in resp.text, path
