"""Links from the application to the documentation website.

The admin docs live in docs/ and are published as a website (mkdocs.yml, built by
Zensical). Anything the app shows an operator — a System check's remedy, a banner, the
in-app admin section — links there rather than naming a repository path, which means
nothing in a browser.

Pure. `page` is the path under docs/ as the repository spells it, so a grep for a page's
file name finds every link to it.
"""

from __future__ import annotations

DOCS_SITE_URL = "https://wagga40.github.io/LogsTotal/"


def docs_url(page: str = "README.md", anchor: str = "") -> str:
    """`runbooks/upgrading.md`, `rollback` -> `…/runbooks/upgrading/#rollback`.

    The site uses directory URLs: `x/y.md` is served at `x/y/`, and a README is its
    directory's index page.
    """
    path = page.removesuffix(".md")
    if path == "README" or path.endswith("/README"):
        path = path.removesuffix("README")
    else:
        path += "/"
    return DOCS_SITE_URL + path.lstrip("/") + (f"#{anchor}" if anchor else "")
