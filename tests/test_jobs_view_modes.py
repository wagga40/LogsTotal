"""Two row shapes for the jobs list, and the one way they can silently disagree.

The compact table caps inline tags at three with a "+N" popover, because as a column they
made the row tall and pushed Score and Status right, and as a `colspan` sub-row they doubled
the length of the list. Both observations are true, which is an argument for two views
rather than one unhappy middle — so `roomy` is a card per job with every tag under a rule,
and `compact` is exactly the table this app has always had.

**The failure mode worth testing is the poll.** `/jobs/table-partial` re-renders the rows
every five seconds while anything is running, and it is a separate route with its own
context dict. A view the page honours and the poll does not looks perfect until the first
tick swaps the other shape in — and only while a job is running, which is precisely when
nobody is looking at the markup.

The clamp is the second one: the preference rides a non-HttpOnly cookie, so it is untrusted
on read, exactly like the theme.
"""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

from app.constants import ALLOWED_JOBS_VIEWS, DEFAULT_JOBS_VIEW, JOBS_VIEW_COOKIE
from app.models import AnalysisJob, JobStatus, JobTag, LogFile, WorkflowDef

pytestmark = pytest.mark.anyio


async def _member(client, async_db) -> None:
    """Tags and checkboxes are member-gated on the list, so anything about them needs one."""
    from tests.test_tag_multi_write import _user

    await _user(async_db, email="v@view.example.com")
    resp = await client.post("/auth/cookie/login", data={"username": "v@view.example.com", "password": "pass123456"})
    assert resp.status_code in (200, 204)


@pytest.fixture()
async def jobs(async_db):
    async_db.add(LogFile(id=1, original_filename="sysmon.evtx", stored_filename="s.evtx", sha256="a" * 64, size_bytes=10, tlsh_hash="T1" + "0" * 68))
    async_db.add(WorkflowDef(id=1, name="Windows Full Analysis"))
    await async_db.commit()
    job = AnalysisJob(submitted_filename="sysmon.evtx", file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    async_db.add(job)
    await async_db.commit()
    await async_db.refresh(job)
    async_db.add_all([JobTag(job_id=job.id, tag=t, color="red") for t in ("apt29", "c2", "triage", "ransomware", "lateral")])
    await async_db.commit()
    return job


class TestTheDefaultIsUnchanged:
    async def test_a_plain_visit_gets_the_table(self, test_client, jobs):
        body = (await test_client.get("/jobs")).text
        assert "<tbody" in body
        assert DEFAULT_JOBS_VIEW == "compact"

    async def test_it_does_not_stamp_a_preference_nobody_expressed(self, test_client, jobs):
        """A first visit — and a shared link with no `?view=` — must not write the cookie."""
        resp = await test_client.get("/jobs")
        assert JOBS_VIEW_COOKIE not in resp.cookies

    async def test_the_poll_url_is_unchanged_without_an_explicit_view(self, test_client, jobs):
        """Pinned because the default view must add nothing to any URL: `?view=compact`
        everywhere would be noise, and it would break the literal this project asserts."""
        body = (await test_client.get("/jobs")).text
        assert 'hx-get="/jobs/table-partial?page=1"' in body


class TestTheRoomyView:
    async def test_it_renders_cards_rather_than_a_table(self, test_client, jobs):
        body = (await test_client.get("/jobs?view=roomy")).text
        # `<tbody`, not `<table`: prose in a comment can contain the latter, and a test that
        # fails on a sentence about tables is a test nobody trusts.
        assert "<tbody" not in body
        assert 'id="jobs-table-body"' in body, "the poll target keeps its id in both views"

    async def test_every_tag_is_shown_with_no_overflow_button(self, test_client, async_db, jobs):
        """This is the point of the view: five tags, all five visible, no "+N"."""
        await _member(test_client, async_db)
        body = (await test_client.get("/jobs?view=roomy")).text
        for tag in ("apt29", "c2", "triage", "ransomware", "lateral"):
            assert f"/jobs?tags={tag}" in body
        assert ">+2<" not in body

    async def test_the_compact_view_still_caps_and_folds(self, test_client, async_db, jobs):
        await _member(test_client, async_db)
        body = (await test_client.get("/jobs?view=compact")).text
        assert ">+2<" in body, "the compact row still folds the tail into a popover"

    async def test_choosing_it_is_remembered(self, test_client, jobs):
        resp = await test_client.get("/jobs?view=roomy")
        assert resp.cookies.get(JOBS_VIEW_COOKIE) == "roomy"

    async def test_the_cookie_alone_selects_it(self, test_client, jobs):
        body = (await test_client.get("/jobs", cookies={JOBS_VIEW_COOKIE: "roomy"})).text
        assert "<tbody" not in body

    async def test_an_explicit_view_beats_the_cookie(self, test_client, jobs):
        body = (await test_client.get("/jobs?view=compact", cookies={JOBS_VIEW_COOKIE: "roomy"})).text
        assert "<tbody" in body


class TestThePollAgreesWithThePage:
    """The whole reason the mode is resolved server-side rather than in Alpine."""

    async def test_the_partial_honours_the_query_param(self, test_client, jobs):
        body = (await test_client.get("/jobs/table-partial?view=roomy")).text
        assert "<tbody" not in body
        assert 'id="jobs-table-body"' in body

    async def test_the_partial_honours_the_cookie_with_no_param(self, test_client, jobs):
        """The case a URL-only implementation gets wrong: the page reads the cookie, the
        poll does not, and five seconds later the list changes shape by itself."""
        body = (await test_client.get("/jobs/table-partial", cookies={JOBS_VIEW_COOKIE: "roomy"})).text
        assert "<tbody" not in body

    async def test_the_poll_url_carries_a_non_default_view(self, test_client, jobs):
        body = (await test_client.get("/jobs?view=roomy")).text
        assert 'hx-get="/jobs/table-partial?page=1&amp;view=roomy"' in body

    async def test_both_views_list_the_same_jobs(self, test_client, jobs):
        compact = (await test_client.get("/jobs/table-partial?view=compact")).text
        roomy = (await test_client.get("/jobs/table-partial?view=roomy")).text
        assert "sysmon.evtx" in compact and "sysmon.evtx" in roomy


class TestItIsUntrustedInput:
    @pytest.mark.parametrize("bad", ["", "list", "<script>", "../etc/passwd", "COMPACT"])
    async def test_an_unknown_view_degrades_to_the_default(self, test_client, jobs, bad):
        resp = await test_client.get("/jobs", params={"view": bad})
        assert resp.status_code == 200
        assert "<tbody" in resp.text

    # No `;` or a leading/trailing space in these: RFC 6265 makes both delimiters, so the
    # client normalises them away and the case would be testing httpx, not the clamp.
    @pytest.mark.parametrize("bad", ["ROOMY", "junk", "roomyroomy", "0"])
    async def test_a_tampered_cookie_degrades_too(self, test_client, jobs, bad):
        """Not HttpOnly, so anything can be in it — and the read side has to clamp, which is
        the `_valid_theme` arrangement."""
        resp = await test_client.get("/jobs", cookies={JOBS_VIEW_COOKIE: bad})
        assert resp.status_code == 200
        assert "<tbody" in resp.text

    async def test_an_unknown_view_is_not_remembered(self, test_client, jobs):
        resp = await test_client.get("/jobs?view=nonsense")
        assert JOBS_VIEW_COOKIE not in resp.cookies

    def test_the_allowed_set_is_a_frozenset_read_by_both_sides(self):
        """One definition, like `ALLOWED_THEMES`. Two would drift and the read side is the
        one that matters."""
        assert isinstance(ALLOWED_JOBS_VIEWS, frozenset)
        assert DEFAULT_JOBS_VIEW in ALLOWED_JOBS_VIEWS


class TestSelectionSurvivesBothViews:
    async def test_the_checkbox_carries_its_data_attribute_in_both(self, test_client, async_db, jobs):
        """`jobSelection` derives select-all from `[data-job-select]` in the DOM, so a view
        that renames or drops that attribute silently breaks the bulk bar."""
        await _member(test_client, async_db)
        for view in ("compact", "roomy"):
            body = (await test_client.get(f"/jobs?view={view}")).text
            assert 'data-job-select="' in body, f"{view} lost the selection hook"
            assert "$store.jobSelection.toggle(" in body, f"{view} lost the store binding"

    async def test_anonymous_gets_no_checkboxes_in_either_view(self, test_client, jobs):
        for view in ("compact", "roomy"):
            body = (await test_client.get(f"/jobs?view={view}")).text
            # `data-job-select` also appears in base.html's store, as the selector it
            # queries — so match the attribute as an element writes it.
            assert 'data-job-select="' not in body, f"{view} exposed the member-only selection"


class TestTheSimilarityMarker:
    """`≈` is a marker on the filename, not a column of its own.

    As a column it was one centred glyph at the far right of a ten-column table — an orphan
    that broke the row's rhythm, and one the card clipped outright for admins: measured at
    1500px, the columns summed to 1459px inside a 1232px card, so the last 96px (the whole
    Delete column) was swallowed by `overflow-hidden`. Beside the filename it sits with the
    padlock and the watch eye, which is where the other per-file markers already live, and
    it is what the roomy view had been doing all along.
    """

    async def test_there_is_no_similarity_column(self, test_client, jobs):
        head = re.search(r"<thead.*?</thead>", (await test_client.get("/jobs")).text, re.S).group(0)
        assert "Similar files" not in head
        assert ">~<" not in head

    async def test_the_marker_rides_beside_the_filename(self, test_client, jobs):
        body = (await test_client.get("/jobs")).text
        assert "&asymp;" in body
        assert "A fuzzy hash exists for this upload" in body

    async def test_a_job_with_no_hash_shows_no_marker(self, test_client, async_db, jobs):
        row = (await async_db.execute(select(LogFile).where(LogFile.id == 1))).scalar_one()
        row.tlsh_hash = None
        await async_db.commit()
        body = (await test_client.get("/jobs")).text
        assert "A fuzzy hash exists for this upload" not in body

    async def test_the_roomy_view_still_spells_it_out(self, test_client, jobs):
        assert "similar" in (await test_client.get("/jobs?view=roomy")).text


class TestTheTableFitsItsCard:
    """The columns have to fit, because the card clips them.

    Measured at 1500px after this: the last column ends 1px inside the card. The two changes
    that bought the room were dropping the orphan `≈` column and folding Client IP under the
    submitter's email — the two-line cell `admin/partials/_activity_table.html` already uses
    for exactly that pair.
    """

    async def test_client_ip_is_not_its_own_column(self, admin_client, jobs):
        head = re.search(r"<thead.*?</thead>", (await admin_client.get("/jobs")).text, re.S).group(0)
        assert "Client IP" not in head
        assert "Submitter" in head

    async def test_the_ip_is_still_shown_under_the_submitter(self, admin_client, async_db, jobs):
        from app.models import AnalysisJob

        job = (await async_db.execute(select(AnalysisJob))).scalars().first()
        job.submitter_ip = "10.11.12.13"
        await async_db.commit()
        assert "10.11.12.13" in (await admin_client.get("/jobs")).text

    async def test_a_wide_table_scrolls_rather_than_being_clipped(self, test_client, jobs):
        """The safety net for a narrow window: `overflow-hidden` on the card rounds the
        corners and would otherwise eat whatever does not fit, silently."""
        body = (await test_client.get("/jobs")).text
        assert "overflow-x-auto" in body


# A one-track grid whose column is `minmax(0, max-content)`: the text inside adds nothing to
# the cell's minimum width but all of itself to its preferred width. An auto-layout table
# never shrinks a column below its minimum, so a `truncate` span on its own (whose minimum is
# the whole unwrapped string) holds the column open however narrow the card. `min-w-[6rem]`
# on the block that fills the cell puts a floor back, so a squeezed column keeps some text.
_NO_MIN = "grid-cols-[minmax(0,max-content)]"
_FLOOR = "min-w-[6rem]"


def _tbody(body: str) -> str:
    return re.search(r"<tbody.*?</tbody>", body, re.S).group(0)


class TestNoCellHoldsTheTableOpen:
    """The rule behind the fit: no text from the data may set a column's minimum width.

    With the admin columns, the table is ten columns in a 1232px card, and it spills over
    once the sum of the column minimums passes 1232px. Measured with realistic worst-case
    rows (a 57-char filename, three tags, an unbroken workflow name, an IPv6 submitter),
    the minimums summed to 1515px, 348px past the card, which pushed the admin Delete
    column behind a horizontal scrollbar at every desktop width. Three cells did it: the
    filename (`truncate`, so its minimum was the whole name, up to the cell's 420px cap),
    the workflow (no cap at all: 325px for one underscored name) and the IPv6 address (not
    truncated, so it spilled 148px out of its 150px cell). With a floor on each, the same
    rows sum to 1080-1091px (dev and production stylesheets) and the table fits from a
    1152px viewport up, in Chromium and Firefox. Ordinary rows lay out exactly as before.
    """

    async def test_the_workflow_name_has_a_floor_not_its_full_width(self, admin_client, jobs):
        body = _tbody((await admin_client.get("/jobs")).text)
        assert re.search(
            r'<span class="grid ' + re.escape(f"{_NO_MIN} {_FLOOR}") + r'">\s*<span class="truncate" title="Windows Full Analysis">Windows Full Analysis</span>',
            body,
        ), "the workflow name must truncate inside a floored grid, with the full name in its title"

    async def test_the_filename_has_the_same_floor(self, admin_client, jobs):
        body = _tbody((await admin_client.get("/jobs")).text)
        assert re.search(
            r'<span class="flex [^"]*' + re.escape(_FLOOR) + r'">\s*<span class="grid ' + re.escape(_NO_MIN) + r'[^"]*">\s*<span class="font-mono[^"]*truncate',
            body,
        )

    async def test_the_tags_wrap_under_the_filename_instead_of_widening_the_row(self, admin_client, jobs):
        """`shrink-0` kept all three chips on one line at full width, so they set the column's
        minimum and, when the column was squeezed anyway, pushed the filename down to a bare
        `≈…`. The chips may wrap now; the filename keeps its floor."""
        body = _tbody((await admin_client.get("/jobs")).text)
        assert "/jobs?tags=apt29" in body, "the fixture's tags must render for this to test anything"
        # The chip's own colour dot is `shrink-0` and should stay so; the container is the one
        # the stopPropagation handler is on.
        containers = re.findall(r'<span class="([^"]*)" onclick="event.stopPropagation\(\)">', body)
        assert containers, "the tag container was not found"
        assert all("shrink-0" not in c.split() for c in containers), containers
        assert re.search(r'<span class="flex flex-wrap items-center[^"]*">\s*<span class="grid ' + re.escape(_NO_MIN), body)

    async def test_the_ip_truncates_inside_its_capped_cell(self, admin_client, async_db, jobs):
        ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        job = (await async_db.execute(select(AnalysisJob))).scalars().first()
        job.submitter_ip = ip
        await async_db.commit()
        body = _tbody((await admin_client.get("/jobs")).text)
        assert re.search(r'<span class="[^"]*\btruncate\b[^"]*" title="' + re.escape(ip) + '">' + re.escape(ip) + "</span>", body)


@pytest.mark.parametrize("view", sorted(ALLOWED_JOBS_VIEWS))
async def test_enter_on_a_control_inside_a_row_is_left_to_that_control(test_client, async_db, jobs, admin_user, view):
    """The row navigates on Enter, and keydown bubbles: Enter on the row's Delete button,
    its "+N" tags button or its checkbox reached the row's handler first and went to the
    job page, so from the keyboard nothing inside a row could be used. The cells stop
    `click`, never `keydown`. The handler has to act only when the row itself is focused."""
    await test_client.post("/auth/cookie/login", data={"username": "admin@test.example.com", "password": "testpass123"})
    body = (await test_client.get(f"/jobs?view={view}")).text

    handlers = re.findall(r'onkeydown="([^"]*)"', body)
    navigating = [h for h in handlers if "window.location" in h]
    assert navigating, "no row-level keyboard handler rendered"
    for h in navigating:
        assert "event.target===event.currentTarget" in h.replace(" ", ""), h
