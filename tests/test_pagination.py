"""The shared pager: a window of page numbers, a way to jump, and the three verbs it navigates with.

`partials/_pager.html` is the one pager in the app. It used to offer Prev, "n / m" and Next
only, so page 15 of a long list was fourteen clicks away. It now draws a fixed-width window
of numbered pages, a "go to page" field once the window elides pages, an optional
"41 to 60 of 359 jobs" range, and a compact variant for the top of a list.

The window is computed by `app/pagination.py::page_window`, a pure function, so its shape is
testable as data. The rendering tests below go through the real macro for each verb — a
link, an htmx swap and the Intel dashboard's Alpine scope — because a variant that renders
a perfect-looking control with the wrong URL is invisible to every route test.
"""

from __future__ import annotations

import re

import pytest

from app.pagination import page_window, qs_pairs, qs_without_page

#: The range separator the pager renders ("41-60 of 359 jobs"), spelled once.
DASH = "\u2013"


class TestPageWindow:
    def test_a_short_list_shows_every_page(self):
        for total in range(1, 10):
            assert page_window(1, total) == list(range(1, total + 1))

    def test_a_long_list_keeps_nine_slots_wherever_you_are(self):
        """A constant width is what keeps Next under the cursor while you click through."""
        for page in range(1, 41):
            window = page_window(page, 40)
            assert len(window) == 9, (page, window)
            assert window[0] == 1 and window[-1] == 40
            assert page in window

    def test_the_start_middle_and_end_shapes(self):
        assert page_window(1, 18) == [1, 2, 3, 4, 5, 6, 7, None, 18]
        assert page_window(5, 18) == [1, 2, 3, 4, 5, 6, 7, None, 18]
        assert page_window(7, 18) == [1, None, 5, 6, 7, 8, 9, None, 18]
        assert page_window(14, 18) == [1, None, 12, 13, 14, 15, 16, 17, 18]
        assert page_window(18, 18) == [1, None, 12, 13, 14, 15, 16, 17, 18]

    def test_an_ellipsis_never_hides_a_single_page(self):
        """`1 … 3` costs the same space as `1 2 3` and hides the page it could have shown."""
        for total in range(10, 30):
            for page in range(1, total + 1):
                window = page_window(page, total)
                for i, item in enumerate(window):
                    if item is None:
                        assert window[i + 1] - window[i - 1] >= 3, (page, total, window)

    def test_an_out_of_range_page_is_clamped(self):
        assert page_window(0, 18) == page_window(1, 18)
        assert page_window(99, 18) == page_window(18, 18)
        assert page_window(1, 0) == [1]


class TestQsPairs:
    def test_the_encoded_filter_becomes_hidden_fields(self):
        assert qs_pairs("tags=a%2Cb&q=is%3Ahits&view=roomy") == [("tags", "a,b"), ("q", "is:hits"), ("view", "roomy")]

    def test_the_form_supplies_its_own_page(self):
        assert qs_pairs("page=3&q=x") == [("q", "x")]

    def test_empty_and_escaped_fragments(self):
        assert qs_pairs("") == []
        assert qs_pairs("q=a+b%26c") == [("q", "a b&c")]
        assert qs_pairs("q=x&amp;view=roomy") == [("q", "x"), ("view", "roomy")]


def _render(page, total_pages, **opts) -> str:
    from app.templates_config import templates

    template = templates.env.from_string('{% from "partials/_pager.html" import pager %}{{ pager(page, total_pages, **opts) }}')
    return template.render(page=page, total_pages=total_pages, opts=opts)


class TestQsWithoutPage:
    def test_a_fragment_without_page_keeps_its_exact_spelling(self):
        for qs in ("", "tags=a%2Cb&q=is%3Ahits", "q=a+b%26c&view=roomy"):
            assert qs_without_page(qs) == qs

    def test_a_stale_page_is_dropped_and_the_filter_kept(self):
        assert qs_without_page("page=2&category=auth") == "category=auth"
        assert qs_without_page("category=auth&amp;page=2&q=a+b") == "category=auth&q=a+b"


class TestTheLinkPager:
    def test_numbered_pages_carry_the_filter(self):
        html = _render(7, 18, url="/jobs", qs="q=x")
        for n in (1, 5, 6, 8, 9, 18):
            assert f'href="/jobs?page={n}&amp;q=x"' in html, n
        assert html.count("…") == 2

    def test_the_current_page_is_marked_and_not_a_link(self):
        html = _render(7, 18, url="/jobs")
        assert re.search(r'aria-current="page"[^>]*>\s*7\s*<', html), html
        assert 'href="/jobs?page=7"' not in html.replace('href="/jobs?page=7&', "")

    def test_the_ends_disable_rather_than_disappear(self):
        first = _render(1, 18, url="/jobs")
        assert 'aria-label="Previous page"' in first and 'aria-disabled="true"' in first
        last = _render(18, 18, url="/jobs")
        assert 'aria-label="Next page"' in last and 'aria-disabled="true"' in last

    def test_prev_and_next_are_marked_for_the_keyboard(self):
        html = _render(7, 18, url="/jobs")
        assert "data-pager-prev" in html and "data-pager-next" in html

    def test_a_single_page_renders_nothing(self):
        assert _render(1, 1, url="/jobs").strip() == ""

    @pytest.mark.parametrize("opts", [{"url": "/x"}, {"url": "/x/partial", "target": "#r"}], ids=["link", "htmx"])
    def test_a_caller_that_passes_its_own_page_still_gets_one_page_per_link(self, opts):
        """A request's own query string carries the page it is on; passed through as the
        filter, every link read `?page=N&page=2` and the last one won — stuck on page 2."""
        html = _render(2, 3, qs="page=2&category=auth", **opts)
        urls = re.findall(r'(?:href|hx-get)="([^"]+)"', html)
        assert urls
        for url in urls:
            assert url.replace("&amp;", "&").count("page=") == 1, url
            assert "category=auth" in url, url


class TestGoToPage:
    def test_it_appears_only_once_the_window_elides_pages(self):
        assert 'name="page"' not in _render(3, 9, url="/jobs")
        assert 'name="page"' in _render(3, 10, url="/jobs")

    def test_a_link_pager_jumps_with_a_plain_get_form_that_keeps_the_filter(self):
        """A real form, so Enter works without JavaScript and the filter rides as fields."""
        html = _render(3, 18, url="/jobs", qs="tags=a%2Cb&q=is%3Ahits")
        form = re.search(r"<form[^>]*>.*?</form>", html, re.S).group(0)
        assert 'method="get"' in form and 'action="/jobs"' in form
        assert '<input type="hidden" name="tags" value="a,b">' in form
        assert '<input type="hidden" name="q" value="is:hits">' in form
        assert 'type="number"' in form and 'min="1"' in form and 'max="18"' in form

    def test_an_htmx_pager_jumps_into_its_own_region(self):
        html = _render(3, 18, url="/x/partial", qs="q=y", target="#region", swap="morph")
        assert 'hx-get="/x/partial?page=4&amp;q=y"' in html
        form = re.search(r"<form[^>]*>", html).group(0)
        assert 'hx-get="/x/partial"' in form and 'hx-target="#region"' in form
        assert 'hx-swap="morph"' in form and 'hx-ext="alpine-morph"' in form

    def test_an_alpine_pager_writes_its_scope(self):
        html = _render(3, 18, alpine="triggerRefresh(false)")
        assert '@click="page = 4; triggerRefresh(false)"' in html
        assert '@click="page = 18; triggerRefresh(false)"' in html
        form = re.search(r"<form[^>]*>", html).group(0)
        assert "@submit.prevent=" in form and "triggerRefresh(false)" in form


class TestRangeAndCompact:
    def test_the_range_says_where_you_are(self):
        assert f"41{DASH}60 of 359 jobs" in _render(3, 18, url="/jobs", total=359, per_page=20, noun="jobs", noun_one="job")
        assert f"341{DASH}359 of 359 jobs" in _render(18, 18, url="/jobs", total=359, per_page=20, noun="jobs", noun_one="job")

    def test_the_compact_pager_is_a_range_and_two_arrows(self):
        html = _render(3, 18, url="/jobs", qs="q=x", total=359, per_page=20, noun="jobs", noun_one="job", compact=True)
        assert f"41{DASH}60 of 359 jobs" in html
        assert 'href="/jobs?page=2&amp;q=x"' in html and 'href="/jobs?page=4&amp;q=x"' in html
        assert "?page=5" not in html and 'name="page"' not in html

    def test_a_single_page_still_says_how_many(self):
        html = _render(1, 1, url="/jobs", total=7, per_page=20, noun="jobs", noun_one="job", compact=True)
        assert "7 jobs" in html and "Previous page" not in html
        assert "1 job" in _render(1, 1, url="/jobs", total=1, per_page=20, noun="jobs", noun_one="job", compact=True)

    def test_keys_are_opt_in(self):
        assert "data-pager-keys" not in _render(3, 18, url="/jobs")
        assert "data-pager-keys" in _render(3, 18, url="/jobs", keys=True)


class TestSmallScreens:
    def test_the_numbers_hide_behind_a_wrapper_never_on_the_buttons(self):
        """`.lt-btn` declares `display`, and the production sheet is linked BEFORE base.html's
        <style>, so a `hidden` on the button itself loses in prod and wins in dev."""
        html = _render(7, 18, url="/jobs")
        assert re.search(r'class="hidden sm:flex[^"]*"', html)
        for attr in re.findall(r'class="([^"]*)"', html):
            classes = attr.split()
            if "lt-btn" in classes:
                assert "hidden" not in classes and not any(c.startswith("sm:") for c in classes), attr

    def test_a_small_screen_still_sees_its_position(self):
        assert re.search(r'class="sm:hidden[^"]*"[^>]*>\s*7 / 18\s*<', _render(7, 18, url="/jobs"))


@pytest.mark.parametrize("path", ["/jobs", "/x/partial"])
def test_the_scroll_box_guard_still_finds_htmx_page_urls(path):
    """`test_lt_scroll_boxes_do_not_swallow_their_pager` keys on `-partial?page=`."""
    html = _render(2, 18, url=path, target="#r")
    assert f"{path}?page=1" in html
