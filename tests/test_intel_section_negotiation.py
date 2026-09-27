"""Tags and Rules each live at exactly one URL.

Each is reachable two ways — as a page an analyst navigates to or bookmarks, and as the
region every action on that page swaps back. Rather than a `/x` + `/x-partial` pair, each
route negotiates on `HX-Request` and renders the *same* context through either the page
template or the region partial.

That is not cosmetic. With a pair, the page route drifts from the partial — re-running the
row queries itself, computing a context key the partial path never gets. Two routes for
one surface drift apart silently; these tests pin one.
"""

from __future__ import annotations

import pytest

from app.models import EntityTag

pytestmark = pytest.mark.anyio

# (url, a string that only the full page renders, a string the region always renders)
SECTIONS = [
    ("/intel/tags", "<!DOCTYPE html>", 'id="tag-manager-region"'),
    ("/intel/rules", "<!DOCTYPE html>", 'id="rules-region"'),
]


@pytest.fixture()
async def tagged(async_db):
    from app.models import Entity

    entity = Entity(value="10.9.9.9", entity_type="ip_address", job_count=1)
    async_db.add(entity)
    await async_db.commit()
    await async_db.refresh(entity)
    async_db.add(EntityTag(entity_id=entity.id, tag="alpha", color="red"))
    await async_db.commit()
    return entity


@pytest.mark.parametrize(("url", "page_marker", "region_marker"), SECTIONS)
async def test_navigation_gets_the_page_and_htmx_gets_the_region(member_client, tagged, url, page_marker, region_marker):
    page = await member_client.get(url)
    assert page.status_code == 200
    assert page_marker in page.text, f"{url}: a plain navigation must render the full page"
    assert region_marker in page.text, f"{url}: the page must embed the same region partial"

    fragment = await member_client.get(url, headers={"HX-Request": "true"})
    assert fragment.status_code == 200
    assert region_marker in fragment.text, f"{url}: an HTMX caller must still get the region"
    assert page_marker not in fragment.text, f"{url}: an HTMX caller must not get page chrome"


@pytest.mark.parametrize(("url", "_page", "_region"), SECTIONS)
async def test_both_representations_vary_on_the_negotiating_header(member_client, tagged, url, _page, _region):
    """Without `Vary`, a cache keyed on the URL alone can serve either shape to the wrong
    caller — a bare fragment to a browser navigation, or a whole page into a tab pane."""
    for headers in ({}, {"HX-Request": "true"}):
        resp = await member_client.get(url, headers=headers)
        assert "hx-request" in resp.headers.get("vary", "").lower(), f"{url}: missing Vary: HX-Request"


async def test_the_dashboard_keeps_no_second_door_to_either(member_client, tagged):
    """Neither has a second door on the dashboard.

    Each spans Jobs *and* Intel, so each is a top-level destination rather than a tab inside
    one of the two surfaces it acts on. The dashboard must not grow a private `-partial`
    twin of either; the nav is where both are reached from.
    """
    html = (await member_client.get("/intel")).text
    for gone in ("sectionUrls", "selectSection", "intel-watch-pane", "watch-partial", "rules-partial"):
        assert gone not in html, f"the Intel dashboard regained a second door: {gone}"
    for href in ('href="/intel/tags"', 'href="/intel/rules"'):
        assert href in html, f"the nav must still offer {href}"


async def test_tag_manager_actions_round_trip_in_the_callers_representation(member_client, tagged):
    """A write from inside the pane must come back as a region, not a nested full page.

    Every tag action re-renders through `_render_tag_manager`, so this covers create/rename/
    merge/recolor/delete at once — they all share the one exit path.
    """
    resp = await member_client.post("/intel/tags", data={"tag": "beta", "color": "blue"}, headers={"HX-Request": "true"})
    assert resp.status_code == 200
    assert 'id="tag-manager-region"' in resp.text
    assert "<!DOCTYPE html>" not in resp.text, "an HTMX write must not nest a whole page inside the pane"


async def test_the_page_context_reaches_both_representations(member_client, tagged):
    """`tagged_entities` is rendered only by the page, but it is computed on the shared path.

    Computed in the page route alone, it would make the two representations diverge — so
    one context, not one template knowing more than the other.
    """
    page = await member_client.get("/intel/tags")
    assert "across 1 entity" in page.text

    # The same request as an HTMX caller must not error on the shared context.
    fragment = await member_client.get("/intel/tags", headers={"HX-Request": "true"})
    assert fragment.status_code == 200


@pytest.mark.parametrize(("url", "_page", "_region"), SECTIONS)
async def test_access_control_is_identical_for_both_representations(test_client, user_client, url, _page, _region):
    """Content negotiation keys off a client-supplied header, so the fragment must never be
    an easier door than the page."""
    for client, expected in ((user_client, {403}), (test_client, {401, 403})):
        for headers in ({}, {"HX-Request": "true"}):
            resp = await client.get(url, headers=headers)
            assert resp.status_code in expected, f"{url} with {headers}: got {resp.status_code}"
