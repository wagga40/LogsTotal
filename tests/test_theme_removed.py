"""One theme, and no theme machinery.

A theme system leaves traces in five places that each fail *silently* rather than loudly.

* a `data-theme` attribute nobody sets, which makes every `[data-theme=…]` rule dead;
* a stylesheet still carrying the removed theme's rules, which nothing selects but everyone
  downloads;
* a switcher in the nav that posts to a route that is gone;
* `User.theme`, a column no code reads;
* a rate-limit bucket for an endpoint that does not exist.

None of those break a page, which is exactly why they survive unless something asserts they
are absent.

A second theme is costlier than it looks: one with `backdrop-filter` on every card makes each
card a stacking context *and* a containing block for `fixed` descendants — so dropdown
layering and popup positioning go wrong in ways that cannot occur in the other theme, and
every menu has to be verified twice.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.anyio

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = REPO_ROOT / "app" / "templates"
THEMES_CSS = REPO_ROOT / "app" / "static" / "themes.css"


# ── no theme route ───────────────────────────────────────────────────────────────────────


async def test_the_theme_endpoint_is_gone(test_client):
    resp = await test_client.post("/settings/theme", data={"theme": "classic"})
    assert resp.status_code == 404


async def test_it_is_not_in_the_route_table(test_client):
    from app.main import app

    assert not [r for r in app.routes if getattr(r, "path", "").startswith("/settings/theme")]


# ── nothing renders a theme ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("url", ["/", "/jobs", "/docs"])
async def test_no_page_carries_a_theme_attribute(test_client, url):
    """With one theme the attribute selects nothing, so rendering it invites a rule keyed on
    a value that will never change."""
    body = (await test_client.get(url)).text
    assert "data-theme" not in body


async def test_the_nav_offers_no_switcher(test_client, admin_client):
    for client in (test_client, admin_client):
        body = (await client.get("/jobs")).text
        assert "themeSwitcher" not in body
        assert "/settings/theme" not in body


def test_the_switcher_partial_is_deleted():
    assert not (TEMPLATES / "partials" / "_theme_switcher.html").exists()
    assert not (REPO_ROOT / "app" / "routers" / "theme.py").exists()


# ── nothing is left behind ───────────────────────────────────────────────────────────────


_COMMENT = re.compile(r"\{#.*?#\}|/\*.*?\*/|<!--.*?-->", re.S)


def _code(path: Path) -> str:
    """A file with its comments stripped.

    The prose that explains *why* the theme was removed mentions it by name, and should —
    that reasoning is the reason the next person does not add it back. What must be gone is
    the live code: selectors, class strings, cookie reads.
    """
    return _COMMENT.sub("", path.read_text())


def test_the_stylesheet_has_one_theme():
    css = _code(THEMES_CSS)
    assert "[data-theme" not in css, "a rule still keys off a theme attribute nothing sets"
    assert "backdrop-filter" not in css, "the glass treatment is what was removed"
    assert re.search(r":root\s*\{", css), "the tokens must still be defined"


def test_nothing_live_still_reads_a_theme():
    haystacks = list(TEMPLATES.rglob("*.html"))
    haystacks += list((REPO_ROOT / "app").rglob("*.py"))
    haystacks += list((REPO_ROOT / "app" / "static").glob("*.js"))
    offenders: list[str] = []
    for path in haystacks:
        code = _code(path)
        for token in ("data-theme", "logstotal_theme", "_theme_switcher", "valid_theme"):
            if token in code:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {token}")
    assert not offenders, f"still reading a theme: {offenders}"


def test_the_user_column_is_gone():
    from app.models import User

    assert not hasattr(User, "theme"), "a column no code reads is a column that will confuse the next reader"


def test_the_rate_limiter_has_no_theme_bucket():
    """The middleware limited `POST /settings/theme`. A bucket for a route that 404s is dead
    configuration that still has to be explained in the docs."""
    from app.middleware.production import AuthRateLimitMiddleware

    paths = [path for _method, path, _kind in AuthRateLimitMiddleware._RATE_LIMITS]
    assert "/settings/theme" not in paths

    from app.config import Settings

    assert not hasattr(Settings(), "theme_rate_limit_per_minute")
