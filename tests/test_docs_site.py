"""The documentation website: what it publishes, and the app's links into it."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from app.docs_site import DOCS_SITE_URL, docs_url
from tests.test_docs_in_sync import _github_slug, _iter_headings

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS = REPO_ROOT / "docs"


class _Loader(yaml.SafeLoader):
    """mkdocs.yml carries `!!python/…` tags for the slugify hook; they are not our subject."""


_Loader.add_multi_constructor("tag:yaml.org,2002:python/", lambda loader, suffix, node: None)


def _nav_pages() -> list[str]:
    config = yaml.load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"), Loader=_Loader)
    pages: list[str] = []

    def walk(node):
        if isinstance(node, str):
            pages.append(node)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)

    walk(config["nav"])
    return pages


def test_docs_url_follows_the_site_layout():
    assert docs_url() == DOCS_SITE_URL
    assert docs_url("runbooks/upgrading.md", "rollback") == DOCS_SITE_URL + "runbooks/upgrading/#rollback"
    assert docs_url("scaling.md") == DOCS_SITE_URL + "scaling/"


def test_every_page_is_in_the_navigation_exactly_once():
    """A page missing from `nav` is built but reachable only by guessing its URL."""
    on_disk = sorted(str(p.relative_to(DOCS)) for p in DOCS.rglob("*.md"))
    nav = _nav_pages()
    assert sorted(nav) == on_disk, f"not in mkdocs.yml nav: {sorted(set(on_disk) - set(nav))}; in nav but missing: {sorted(set(nav) - set(on_disk))}"
    assert len(nav) == len(set(nav)), "a page is listed twice in the navigation"


_CALL = re.compile(r"""docs_url\(\s*['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]*)['"])?\s*\)""")


def _calls():
    for path in [*(REPO_ROOT / "app").rglob("*.py"), *(REPO_ROOT / "app" / "templates").rglob("*.html")]:
        if path.name == "docs_site.py":
            continue
        for page, anchor in _CALL.findall(path.read_text(encoding="utf-8")):
            yield path.relative_to(REPO_ROOT), page, anchor


def test_the_app_links_only_to_pages_and_anchors_that_exist():
    calls = list(_calls())
    assert len(calls) >= 4, "the scan no longer finds the app's docs_url() calls"
    for where, page, anchor in calls:
        target = DOCS / page
        assert target.is_file(), f"{where} links to docs/{page}, which does not exist"
        if anchor:
            slugs = {_github_slug(h) for h in _iter_headings(target)}
            assert anchor in slugs, f"{where} links to docs/{page}#{anchor}, which has no such heading"


@pytest.mark.parametrize("path", ["app/system_checks.py", "app/routers/admin.py", "app/templates/admin/partials/_concurrency.html"])
def test_what_an_operator_reads_names_no_repository_path(path: str):
    """`docs/scaling.md` in a remedy means nothing in a browser; the website does."""
    text = (REPO_ROOT / path).read_text(encoding="utf-8")
    shown = [line for line in text.splitlines() if re.search(r"""["'].*docs/[a-z/_-]+\.md""", line) and not line.lstrip().startswith("#")]
    assert not shown, f"{path} shows a repository path to the operator: {shown}"
