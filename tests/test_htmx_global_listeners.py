"""A page-wide htmx listener goes on `document`, never on `document.body`.

htmx 4 dispatches an event whose element has left the page at `document` itself
(`trigger()`: `n = e?.isConnected ? e : document`), and an event dispatched on the document
does not travel down to `<body>`. So a body listener is deaf to exactly the requests that
replace their own element. The Explore and AI analysis tabs lazy-load that way: their
`finally:request` landed on the document, `app.js` never cleared the wait cursor it had set
on `before:request`, and the pointer spun over a fully loaded page until some other request
happened to finish. Nothing errors and every route test passes, which is why this is a
grep over the source rather than a behaviour test.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"
TEMPLATES = ROOT / "app" / "templates"
HTMX = STATIC / "vendor" / "htmx.min.js"

BODY_LISTENER = re.compile(r"""document\.body\.addEventListener\(\s*['"]htmx:""")
DOC_LISTENER = re.compile(r"""\bdocument\.addEventListener\(\s*['"](htmx:[a-z:]+)['"]""")


def _sources() -> list[Path]:
    return sorted(STATIC.glob("*.js")) + sorted(TEMPLATES.rglob("*.html"))


def test_the_vendored_htmx_still_retargets_a_detached_elements_events_to_document():
    """The premise of this file. If an htmx upgrade drops it, re-derive the rule below."""
    assert "isConnected?e:document" in HTMX.read_text(encoding="utf-8")


def test_no_htmx_listener_is_attached_to_body():
    offenders = [
        f"{path.relative_to(ROOT)}:{text.count(chr(10), 0, m.start()) + 1}"
        for path in _sources()
        for text in [path.read_text(encoding="utf-8")]
        for m in BODY_LISTENER.finditer(text)
    ]
    assert not offenders, f"htmx listeners on document.body miss events from swapped-out elements: {offenders}"


def test_the_wait_cursor_is_set_and_cleared_on_document():
    """The pair that showed the bug: both halves must hear the same requests."""
    app_js = (STATIC / "app.js").read_text(encoding="utf-8")
    events = set(DOC_LISTENER.findall(app_js))
    assert {"htmx:before:request", "htmx:finally:request"} <= events
    clear = app_js[app_js.index("'htmx:finally:request'") :][:200]
    assert "cursor = ''" in clear
