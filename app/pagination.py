"""The arithmetic behind `partials/_pager.html` — pure, so the shape is testable as data.

Registered as Jinja globals in `app/templates_config.py`; nothing here touches a request,
a session or a template.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode

#: Pages shown either side of the current one. The window is `1 … p-2 p-1 p p+1 p+2 … N`:
#: nine slots whenever there are more than nine pages, so the control keeps one width and
#: Next stays under the cursor while you click through.
RADIUS = 2
_SLOTS = 2 * RADIUS + 5


def page_window(page: int, total_pages: int) -> list[int | None]:
    """The page numbers to draw, with `None` where an ellipsis stands for the pages between.

    Near either end the window slides rather than shrinks, and an ellipsis always hides at
    least two pages — `1 … 3` takes the room of `1 2 3` and hides the page it could show.
    """
    total_pages = max(1, total_pages)
    if total_pages <= _SLOTS:
        return list(range(1, total_pages + 1))
    page = min(max(page, 1), total_pages)
    edge = _SLOTS - 2  # first or last page, then the run beside it, then an ellipsis
    if page <= RADIUS + 3:
        return [*range(1, edge + 1), None, total_pages]
    if page >= total_pages - RADIUS - 2:
        return [1, None, *range(total_pages - edge + 1, total_pages + 1)]
    return [1, None, *range(page - RADIUS, page + RADIUS + 1), None, total_pages]


def qs_pairs(qs: str) -> list[tuple[str, str]]:
    """An already-encoded query fragment as `(name, value)` pairs, minus any `page`.

    The go-to-page field is a real GET form, so the filter has to travel as hidden inputs
    rather than as the fragment the links append — and the form supplies its own `page`.
    Tolerates `&amp;`, since some callers hand over a fragment escaped for an attribute.
    """
    return [(k, v) for k, v in parse_qsl(qs.replace("&amp;", "&"), keep_blank_values=True) if k != "page"]


def qs_without_page(qs: str) -> str:
    """The fragment a pager link appends after its own `page=N` — minus any `page` it held.

    A caller that passes a query string straight through (the request's own, say) hands
    over the page it is on. The link then reads `?page=3&page=2`, the last one wins, and
    the list sticks on page 2 whatever is clicked. Returned untouched when it has no
    `page`, so a well-built fragment keeps its exact spelling.
    """
    pairs = parse_qsl(qs.replace("&amp;", "&"), keep_blank_values=True)
    if all(k != "page" for k, _ in pairs):
        return qs
    return urlencode([(k, v) for k, v in pairs if k != "page"])
