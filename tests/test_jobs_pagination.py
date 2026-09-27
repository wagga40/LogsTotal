"""Paging through a long jobs list: a stable order, no dead pages, and a choice of page size.

Three failures this pins, each measured on a real instance before it was fixed:

- **Tied timestamps split across pages.** `created_at` has one-second resolution and a
  multi-file upload creates jobs in bursts — 359 jobs shared 54 distinct timestamps, up to
  17 in one second. Ordered by `created_at` alone, ties came back in arbitrary order, so a
  page boundary through a burst could show a job twice or never. The id breaks the tie.
- **A page past the end said there were no jobs at all.** `?page=999` rendered the empty
  state ("No jobs yet") with no pager to get back. It now lands on the last page.
- **Rows per page** is `?per=` + a cookie, the `?view=` arrangement: the 5s table poll must
  honour it, so it rides `list_qs` — and the default adds nothing to any URL.
"""

from __future__ import annotations

import re
from datetime import datetime

import pytest

from app.constants import DEFAULT_JOBS_PER_PAGE, JOBS_PER_PAGE_CHOICES, JOBS_PER_PAGE_COOKIE
from app.models import AnalysisJob, JobStatus, LogFile, WorkflowDef

pytestmark = pytest.mark.anyio

#: The range separator the pager renders ("41-60 of 359 jobs"), spelled once.
DASH = "\u2013"


@pytest.fixture()
async def burst(async_db):
    """45 public jobs created in the same second, as one multi-file upload makes them."""
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="Windows Full Analysis"))
    await async_db.commit()
    same_second = datetime(2026, 9, 26, 14, 26, 12)
    jobs = [AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False, created_at=same_second) for _ in range(45)]
    async_db.add_all(jobs)
    await async_db.commit()
    return sorted((j.id for j in jobs), reverse=True)


def _ids(html: str) -> list[int]:
    """Job ids in the order their rows appear, once each. Rows navigate by `onclick`; their
    `aria-label` is the stable handle."""
    seen: list[int] = []
    for match in re.finditer(r'aria-label="Job #(\d+)', html):
        job_id = int(match.group(1))
        if job_id not in seen:
            seen.append(job_id)
    return seen


async def test_tied_jobs_are_paged_by_id_each_exactly_once(test_client, burst):
    pages = [_ids((await test_client.get(f"/jobs/table-partial?page={n}")).text) for n in (1, 2, 3)]
    assert [len(p) for p in pages] == [20, 20, 5]
    assert [job_id for page in pages for job_id in page] == burst


async def test_a_page_past_the_end_lands_on_the_last_page(test_client, burst):
    body = (await test_client.get("/jobs?page=999")).text
    assert "No jobs yet" not in body
    assert _ids(body.split("<tbody", 1)[1]) == burst[40:]
    assert f"41{DASH}45 of 45 jobs" in body


async def test_the_list_says_where_you_are_and_offers_to_jump(test_client, burst):
    body = (await test_client.get("/jobs?page=2")).text
    assert f"21{DASH}40 of 45 jobs" in body
    assert "data-pager-keys" in body


class TestRowsPerPage:
    async def test_the_choices_and_the_default(self):
        assert DEFAULT_JOBS_PER_PAGE == 20
        assert DEFAULT_JOBS_PER_PAGE in JOBS_PER_PAGE_CHOICES

    async def test_an_explicit_choice_is_honoured_and_remembered(self, test_client, burst):
        resp = await test_client.get("/jobs?per=50")
        assert len(_ids(resp.text.split("<tbody", 1)[1])) == 45
        assert resp.cookies.get(JOBS_PER_PAGE_COOKIE) == "50"
        assert 'hx-get="/jobs/table-partial?page=1&amp;per=50"' in resp.text

    async def test_the_poll_honours_it(self, test_client, burst):
        assert len(_ids((await test_client.get("/jobs/table-partial?page=1&per=50")).text)) == 45

    async def test_the_cookie_alone_selects_it(self, test_client, burst):
        test_client.cookies.set(JOBS_PER_PAGE_COOKIE, "100")
        body = (await test_client.get("/jobs")).text
        assert len(_ids(body.split("<tbody", 1)[1])) == 45
        assert "per=100" in body

    @pytest.mark.parametrize("value", ["1000", "0", "-5", "abc", "20.5"])
    async def test_an_unknown_value_degrades_to_the_default_and_is_not_stored(self, test_client, burst, value):
        resp = await test_client.get(f"/jobs?per={value}")
        assert resp.status_code == 200
        assert len(_ids(resp.text.split("<tbody", 1)[1])) == DEFAULT_JOBS_PER_PAGE
        assert JOBS_PER_PAGE_COOKIE not in resp.cookies

    async def test_a_tampered_cookie_degrades_too(self, test_client, burst):
        test_client.cookies.set(JOBS_PER_PAGE_COOKIE, "999999")
        body = (await test_client.get("/jobs")).text
        assert len(_ids(body.split("<tbody", 1)[1])) == DEFAULT_JOBS_PER_PAGE

    async def test_the_default_adds_nothing_to_any_url(self, test_client, burst):
        body = (await test_client.get("/jobs")).text
        assert 'hx-get="/jobs/table-partial?page=1"' in body
        assert 'href="/jobs?page=2"' in body

    async def test_switching_keeps_the_first_row_you_were_looking_at(self, test_client, burst):
        """Page 3 at 20 per page starts at row 41, which is on page 1 at 50 and at 100."""
        body = (await test_client.get("/jobs?page=3")).text
        assert 'href="/jobs?per=20&amp;page=3"' in body
        assert 'href="/jobs?per=50&amp;page=1"' in body
        assert 'href="/jobs?per=100&amp;page=1"' in body

    async def test_the_filter_survives_a_switch(self, test_client, burst):
        body = (await test_client.get("/jobs?q=status%3Acompleted")).text
        assert 'href="/jobs?per=50&amp;page=1&amp;q=status%3Acompleted"' in body
