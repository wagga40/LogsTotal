"""Analyst tags on jobs.

The same vocabulary entities use, hung off a second link table. Most of what is worth
pinning here is not "does a tag save" but the three ways this feature can look correct and
be wrong:

* **the twin queries.** `/jobs` and `/jobs/table-partial` are the page and its 5-second
  poll, and they share one query. A filter applied to one and not the
  other looks perfect until the first poll silently swaps in an unfiltered set — and only
  while a job is running, so it is invisible to a test that does not have one.
* **the URL fragments.** The filter has to ride the poll URL *and* the pager, and each is a
  separate place to forget it.
* **visibility.** Tagging writes, so it must check `can_view_job` first, or the response
  differs between "tagged" and "no such job" and becomes an existence oracle for another
  member's private submission.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import AnalysisJob, JobStatus, JobTag, LogFile, TagDefinition, User, WorkflowDef

pytestmark = pytest.mark.anyio


async def _user(async_db, *, email: str, role: str = "member", superuser: bool = False) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    return await UserManager(user_db).create(UserCreate(email=email, password="pass123456", is_superuser=superuser, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"})
    assert resp.status_code in (200, 204)


@pytest.fixture()
async def data(async_db):
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    await async_db.commit()

    owner = await _user(async_db, email="owner@jt.example.com")
    other = await _user(async_db, email="other@jt.example.com")
    basic = await _user(async_db, email="basic@jt.example.com", role="user")
    await _user(async_db, email="admin@jt.example.com", role="admin", superuser=True)

    public = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    second = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    private = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner.id)
    async_db.add_all([public, second, private])
    await async_db.commit()
    for obj in (public, second, private, owner, other, basic):
        await async_db.refresh(obj)
    return {"public": public, "second": second, "private": private, "owner": owner, "other": other, "basic": basic}


@pytest.fixture()
async def member_client(test_client, data):
    await _login(test_client, "other@jt.example.com")
    return test_client


# ── Applying a tag ───────────────────────────────────────────────────────────


async def test_adding_a_tag_registers_it_in_the_shared_vocabulary(member_client, async_db, data):
    """A tag first coined on a job must still exist in the picker afterwards — the same
    contract the entity path has, and the reason `TagDefinition` exists at all."""
    job_id = data["public"].id
    resp = await member_client.post(f"/jobs/{job_id}/tags", data={"tag": "APT29", "color": "red"})
    assert resp.status_code == 200

    rows = (await async_db.execute(select(JobTag).where(JobTag.job_id == job_id))).scalars().all()
    assert [(r.tag, r.color) for r in rows] == [("apt29", "red")], "normalised to lowercase"
    assert (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "apt29"))).scalar_one_or_none() is not None


async def test_re_adding_recolours_rather_than_duplicating(member_client, async_db, data):
    job_id = data["public"].id
    await member_client.post(f"/jobs/{job_id}/tags", data={"tag": "apt29", "color": "red"})
    await member_client.post(f"/jobs/{job_id}/tags", data={"tag": "apt29", "color": "blue"})

    rows = (await async_db.execute(select(JobTag).where(JobTag.job_id == job_id))).scalars().all()
    assert len(rows) == 1
    assert rows[0].color == "blue"


async def test_removing_a_tag(member_client, async_db, data):
    job_id = data["public"].id
    await member_client.post(f"/jobs/{job_id}/tags", data={"tag": "apt29"})
    resp = await member_client.post(f"/jobs/{job_id}/tags/remove", data={"tag": "apt29"})

    assert resp.status_code == 200
    assert (await async_db.execute(select(JobTag).where(JobTag.job_id == job_id))).scalars().all() == []


async def test_removing_a_tag_with_a_slash_from_the_job_header(member_client, async_db, data):
    """The x on the chip sends the tag in the path; with `/` in it the route never matched."""
    import re

    job_id = data["public"].id
    await member_client.post(f"/jobs/{job_id}/tags", data={"tag": "ttp/t1059"})
    body = (await member_client.get(f"/jobs/{job_id}")).text
    url = re.search(r'hx-post="(/jobs/\d+/tags/remove)"', body).group(1)

    assert (await member_client.post(url, data={"tag": "ttp/t1059"})).status_code == 200
    assert (await async_db.execute(select(JobTag).where(JobTag.job_id == job_id))).scalars().all() == []


async def test_a_built_in_label_name_is_accepted(member_client, data):
    """Labels are rules that write tags, so this is an ordinary tag — the same 200 the
    entity path gives."""
    resp = await member_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "lolbin"})
    assert resp.status_code == 200


# ── Who may tag ──────────────────────────────────────────────────────────────


async def test_a_plain_user_cannot_tag(test_client, async_db, data):
    """Applying a tag writes to the instance-wide vocabulary Intel curates. Letting the one
    role with no Intel access reshape it would be backwards."""
    await _login(test_client, "basic@jt.example.com")
    resp = await test_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "nope"})
    assert resp.status_code == 403
    assert (await async_db.execute(select(JobTag))).scalars().all() == []


async def test_anonymous_cannot_tag(test_client, async_db, data):
    resp = await test_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "nope"})
    assert resp.status_code in (401, 403)
    assert (await async_db.execute(select(JobTag))).scalars().all() == []


async def test_tagging_another_members_private_job_is_a_404(member_client, async_db, data):
    """404, not 403 — byte-identical to a job that does not exist, so this cannot be used
    to discover that one does."""
    resp = await member_client.post(f"/jobs/{data['private'].id}/tags", data={"tag": "peek"})
    assert resp.status_code == 404

    missing = await member_client.post("/jobs/999999/tags", data={"tag": "peek"})
    assert missing.status_code == 404
    assert (await async_db.execute(select(JobTag))).scalars().all() == []


# ── Bulk ─────────────────────────────────────────────────────────────────────


async def test_bulk_tag_applies_to_every_selected_job(member_client, async_db, data):
    ids = f"{data['public'].id},{data['second'].id}"
    resp = await member_client.post("/jobs/bulk-tag", data={"job_ids": ids, "tag": "triage", "color": "amber"})

    assert resp.status_code == 200
    rows = (await async_db.execute(select(JobTag).where(JobTag.tag == "triage"))).scalars().all()
    assert {r.job_id for r in rows} == {data["public"].id, data["second"].id}


def test_the_id_list_drops_what_the_database_cannot_take():
    """Documented as "non-numeric entries dropped": a superscript digit passes isdigit() and
    then raises in int(), and an id past int4 is a bind error on PostgreSQL."""
    from app.tags import parse_id_csv

    assert parse_id_csv("1,²,①,3,99999999999999999999,2147483648", 10) == [1, 3]


async def test_bulk_tag_with_a_non_ascii_digit_is_not_a_500(member_client, async_db, data):
    resp = await member_client.post("/jobs/bulk-tag", data={"job_ids": f"{data['public'].id},²", "tag": "triage"})
    assert resp.status_code == 200


async def test_bulk_tag_silently_skips_invisible_jobs(member_client, async_db, data):
    """Selecting a page that happens to include someone else's private job should tag what
    you can see — not 404 and name the job you were not supposed to know about."""
    ids = f"{data['public'].id},{data['private'].id}"
    resp = await member_client.post("/jobs/bulk-tag", data={"job_ids": ids, "tag": "triage"})

    assert resp.status_code == 200
    rows = (await async_db.execute(select(JobTag).where(JobTag.tag == "triage"))).scalars().all()
    assert {r.job_id for r in rows} == {data["public"].id}


async def test_bulk_tag_is_idempotent(member_client, async_db, data):
    ids = str(data["public"].id)
    await member_client.post("/jobs/bulk-tag", data={"job_ids": ids, "tag": "triage"})
    await member_client.post("/jobs/bulk-tag", data={"job_ids": ids, "tag": "triage"})

    rows = (await async_db.execute(select(JobTag).where(JobTag.tag == "triage"))).scalars().all()
    assert len(rows) == 1


async def test_bulk_untag(member_client, async_db, data):
    ids = f"{data['public'].id},{data['second'].id}"
    await member_client.post("/jobs/bulk-tag", data={"job_ids": ids, "tag": "triage"})
    await member_client.post("/jobs/bulk-untag", data={"job_ids": ids, "tag": "triage"})

    assert (await async_db.execute(select(JobTag).where(JobTag.tag == "triage"))).scalars().all() == []


# ── The filter, and the three places it has to survive ───────────────────────


async def test_the_filter_narrows_the_list(member_client, async_db, data):
    await member_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "triage"})

    body = (await member_client.get("/jobs?tags=triage")).text
    assert f"/jobs/{data['public'].id}" in body
    assert f"/jobs/{data['second'].id}" not in body


async def test_the_page_and_its_poll_agree(member_client, async_db, data):
    """The twin-query trap. These two are the page and its 5s poll; a filter on one and not
    the other is invisible until a job happens to be running."""
    await member_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "triage"})

    page = (await member_client.get("/jobs?tags=triage")).text
    partial = (await member_client.get("/jobs/table-partial?tags=triage")).text

    assert f"/jobs/{data['second'].id}" not in page
    assert f"/jobs/{data['second'].id}" not in partial, "the poll must apply the same filter as the page"
    assert f"/jobs/{data['public'].id}" in partial


@pytest.mark.parametrize("login", [None, "basic@jt.example.com"])
@pytest.mark.parametrize("filter_qs", ["tags={tag}", "q=tag:{tag}"])
async def test_a_tag_filter_tells_a_non_member_nothing(test_client, async_db, data, login, filter_qs):
    """Tags are member-only, so the list hides them from anonymous and `role=user` viewers.
    The filter did not: a list narrowing to exactly the tagged job confirmed the label, and
    guessing names ('false-positive', 'apt29') read out the analysts' triage state."""
    async_db.add(JobTag(job_id=data["public"].id, tag="insider-suspect", color="red"))
    await async_db.commit()
    if login:
        await _login(test_client, login)

    def jobs_shown(body):
        return {j.id for j in (data["public"], data["second"]) if f"/jobs/{j.id}" in body}

    for path in ("/jobs", "/jobs/table-partial"):
        real = (await test_client.get(f"{path}?{filter_qs.format(tag='insider-suspect')}")).text
        guess = (await test_client.get(f"{path}?{filter_qs.format(tag='no-such-tag')}")).text
        assert jobs_shown(real) == jobs_shown(guess), path
        assert "insider-suspect" not in real.replace("q=tag%3Ainsider-suspect", "").replace("tags=insider-suspect", "").replace('value="tag:insider-suspect"', "")


async def test_the_poll_url_carries_the_filter(test_client, async_db, data):
    """Rendered only while something is running — which is exactly when the poll fires, and
    exactly the case a test without a running job cannot see."""
    running = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.RUNNING, is_private=False)
    async_db.add(running)
    await async_db.commit()
    await async_db.refresh(running)
    # It has to carry the tag as well as be running: under the filter, an untagged job is
    # not in the list, so `has_running` is false and no poll is rendered to inspect.
    async_db.add(JobTag(job_id=running.id, tag="triage", color="gray"))
    await async_db.commit()
    await _login(test_client, "other@jt.example.com")

    body = (await test_client.get("/jobs?tags=triage")).text
    assert 'hx-get="/jobs/table-partial?page=1&amp;tags=triage"' in body


async def test_the_pager_carries_the_filter(member_client, async_db, data):
    """Page 2 of a filtered list must still be filtered."""
    for _ in range(25):
        job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
        async_db.add(job)
        await async_db.commit()
        await async_db.refresh(job)
        async_db.add(JobTag(job_id=job.id, tag="bulky", color="gray"))
    await async_db.commit()

    body = (await member_client.get("/jobs?tags=bulky")).text
    assert "/jobs?page=2&amp;tags=bulky" in body


async def test_the_count_is_filtered_too(member_client, async_db, data):
    """An unfiltered count offers pages the filter cannot fill."""
    for _ in range(25):
        async_db.add(AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False))
    await async_db.commit()
    await member_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "rare"})

    body = (await member_client.get("/jobs?tags=rare")).text
    assert "/jobs?page=2" not in body, "one match must not paginate"


async def test_an_empty_filtered_list_says_why(member_client, data):
    body = (await member_client.get("/jobs?tags=nothing-carries-this")).text
    assert "No jobs yet" not in body, "that would read as 'your uploads vanished'"
    assert "No jobs match that search" in body


# ── Where the region may live ────────────────────────────────────────────────


def test_the_tags_region_never_enters_the_polling_partial():
    """`#job-status-region` morph-swaps every 3s while a job runs. A tag input inside it
    would lose whatever was half-typed on every tick — the same rule the comment thread
    follows, and the same reason."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "app" / "templates"
    status = (root / "partials" / "_job_status.html").read_text()
    assert "_job_header_tags.html" not in status
    assert "job-tags-region" not in status

    page = (root / "job.html").read_text()
    assert "_job_header_tags.html" in page, "...but it does have to be on the page"


async def test_a_plain_user_gets_no_tag_controls(test_client, async_db, data):
    """The picker fetches /intel/tags.json, which is member+. Rendered for a `role=user` it
    would be a silent 403 and a permanently empty combobox."""
    await _login(test_client, "basic@jt.example.com")
    body = (await test_client.get(f"/jobs/{data['public'].id}")).text
    assert "job-tags-region" not in body


# ── The list has to refresh, and the tag box has to know about new tags ──────
#
# Both of these are stale-client bugs: the server was right and the browser was showing
# something older. Neither is visible to a test that only checks a POST's own response.


async def test_the_table_can_be_refreshed_without_a_running_job(test_client, async_db, data):
    """The bulk bar triggers `jobsRefresh` after a write.

    Inside `{% if has_running %}`, the hx-get/hx-swap would leave nothing to trigger when no
    job is running, and a bulk tag would leave every row stale until reload.
    """
    await _login(test_client, "other@jt.example.com")
    body = (await test_client.get("/jobs")).text

    assert 'hx-get="/jobs/table-partial' in body, "the table must be refreshable at rest"
    assert "jobsRefresh from:body" in body
    assert "every 5s" not in body, "...but it must not poll when nothing is running"


async def test_the_poll_is_still_conditional(test_client, async_db, data):
    """The refresh hook must not turn the table into an unconditional poller."""
    running = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.RUNNING, is_private=False)
    async_db.add(running)
    await async_db.commit()
    await _login(test_client, "other@jt.example.com")

    body = (await test_client.get("/jobs")).text
    assert "jobsRefresh from:body, every 5s" in body


async def test_the_bulk_bar_triggers_the_refresh(test_client, async_db, data):
    await _login(test_client, "other@jt.example.com")
    body = (await test_client.get("/jobs")).text
    assert "htmx.trigger('#jobs-table-body', 'jobsRefresh')" in body


def test_every_tag_write_invalidates_the_vocabulary_cache():
    """`tagCombobox` caches its tag list per instance and latches `loaded`.

    Without invalidation, a tag coined in the bulk bar is missing from the very box it was
    typed into on the next open — and from every other combobox on the page. `window.` form
    required: the Alpine identifier checker harvests page globals only from inline scripts,
    so a bare call under a literal x-data scope reads as unresolved.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "app"
    app_js = (root / "static" / "app.js").read_text()
    assert "__ltTagGeneration" in app_js
    assert "window.tagVocabChanged = tagVocabChanged" in app_js

    writers = [
        root / "templates" / "intel" / "partials" / "_entity_bulk_actions.html",
        root / "templates" / "intel" / "partials" / "_entity_header_tags.html",
        root / "templates" / "intel" / "partials" / "_tag_manager_table.html",
        root / "templates" / "partials" / "_job_header_tags.html",
        root / "templates" / "partials" / "_jobs_bulk_actions.html",
    ]
    for path in writers:
        text = path.read_text()
        assert "window.tagVocabChanged()" in text, f"{path.name} writes tags without invalidating the picker"


async def test_tags_ride_inline_after_the_filename(test_client, async_db, data):
    """As a column they made the row tall and pushed Score and Status right; as a sub-row
    they doubled the list's length. Inline, capped, they are a property of the thing they
    sit beside and the row height never moves."""
    import re

    await _login(test_client, "other@jt.example.com")
    await test_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "triage"})

    html = (await test_client.get("/jobs")).text
    head = re.search(r"<thead.*?</thead>", html, re.S).group(0)
    assert "Tags</th>" not in head, "no tags column"

    body = re.search(r'<tbody id="jobs-table-body".*?</tbody>', html, re.S).group(0)
    assert "colspan=" not in body, "no tag sub-row"
    assert "/jobs?tags=triage" in body, "...but the chip is there, and it filters"


async def test_only_the_first_few_tags_render_inline(test_client, async_db, data):
    """The cap is what keeps the row height fixed. The rest are reachable, not dropped."""
    import re

    from app.models import JobTag

    for name in ("alpha", "bravo", "charlie", "delta", "echo"):
        async_db.add(JobTag(job_id=data["public"].id, tag=name, color="gray"))
    await async_db.commit()
    await _login(test_client, "other@jt.example.com")

    body = re.search(r'<tbody id="jobs-table-body".*?</tbody>', (await test_client.get("/jobs")).text, re.S).group(0)

    assert ">+2<" in body, "the overflow count must say how many are hidden"
    # Every tag is still present and still a filter link — "+2" opens them, it does not
    # replace them with a dead label.
    for name in ("alpha", "bravo", "charlie", "delta", "echo"):
        assert f"/jobs?tags={name}" in body, f"{name} is unreachable"


async def test_the_overflow_panel_is_scoped_per_row(test_client, async_db, data):
    """One `x-data` per overflow button, or opening one job's extra tags opens every job's."""
    import re

    from app.models import JobTag

    for job in (data["public"], data["second"]):
        for name in ("a1", "b2", "c3", "d4"):
            async_db.add(JobTag(job_id=job.id, tag=name, color="gray"))
    await async_db.commit()
    await _login(test_client, "other@jt.example.com")

    body = re.search(r'<tbody id="jobs-table-body".*?</tbody>', (await test_client.get("/jobs")).text, re.S).group(0)
    # The overflow reveals the rest inline rather than in a floating panel — a `fixed` panel
    # is positioned against the nearest `backdrop-filter` ancestor, not the viewport, which
    # can put it hundreds of pixels off. The per-row scoping still matters.
    assert body.count('x-data="{ open: false }"') == 2, "each row needs its own open state"


async def test_a_watched_job_is_marked_in_the_list(test_client, async_db, data):
    """Otherwise the only way to know is to open the job and look at the button."""
    import re

    from app import job_watch

    await _login(test_client, "other@jt.example.com")
    before = re.search(r'<tbody id="jobs-table-body".*?</tbody>', (await test_client.get("/jobs")).text, re.S).group(0)
    assert "You are watching this job" not in before

    await job_watch.ensure_watch_async(async_db, data["public"].id, data["other"].id)
    await async_db.commit()

    after = re.search(r'<tbody id="jobs-table-body".*?</tbody>', (await test_client.get("/jobs")).text, re.S).group(0)
    assert after.count("You are watching this job") == 1, "exactly the watched row is marked"


async def test_the_watched_marker_is_per_viewer(test_client, async_db, data):
    """It is *your* subscription, not a property of the job."""
    import re

    from app import job_watch

    await job_watch.ensure_watch_async(async_db, data["public"].id, data["other"].id)
    await async_db.commit()

    await _login(test_client, "owner@jt.example.com")
    body = re.search(r'<tbody id="jobs-table-body".*?</tbody>', (await test_client.get("/jobs")).text, re.S).group(0)
    assert "You are watching this job" not in body


# ── The jobs-page tab strip ──────────────────────────────────────────────────


async def test_the_strip_is_gated_in_the_tab_list_not_in_the_markup(test_client, async_db, data):
    """`/jobs` is anonymous-viewable, so a tab whose pane 403s is worse than no tab. Gating
    lives in `_build_jobs_page_tabs`; anonymous gets one entry and no strip at all."""
    anon = (await test_client.get("/jobs")).text
    assert "resourceTabs(" not in anon, "anonymous gets the bare table"
    assert "loadJobTags" not in anon

    await _login(test_client, "basic@jt.example.com")
    plain = (await test_client.get("/jobs")).text
    assert "loadJobWatching" in plain, "any logged-in user may watch"

    await _login(test_client, "other@jt.example.com")
    assert "loadJobWatching" in (await test_client.get("/jobs")).text


async def test_the_panes_serve_a_fragment_and_a_page(test_client, async_db, data):
    """One URL, two representations — `negotiated()`, so a tab and its bookmarkable page
    cannot drift."""
    await _login(test_client, "other@jt.example.com")

    page = await test_client.get("/jobs/watching")
    assert "<html" in page.text, "a plain navigation gets the whole page"
    assert "HX-Request" in page.headers.get("vary", ""), "the two share a URL, so Vary is required"

    frag = await test_client.get("/jobs/watching", headers={"HX-Request": "true"})
    assert "<html" not in frag.text
    assert 'id="jobs-watching-region"' in frag.text


async def test_a_swapped_pane_does_not_re_arm_its_lazy_trigger(test_client, async_db, data):
    """`resourceTabs.select()` re-dispatches the lazy event on EVERY activation, and `once`
    is per listener. A fragment root that redeclared its own trigger would refetch on the
    next tab switch, forever."""
    await _login(test_client, "other@jt.example.com")

    frag = (await test_client.get("/jobs/watching", headers={"HX-Request": "true"})).text
    assert "hx-trigger" not in frag, "the fragment re-arms its own lazy trigger"


async def test_the_tag_manager_pivots_to_both_lists(test_client, async_db, data):
    """The manager is the hub you leave from: one count per surface, each a link into the
    list it describes. A zero is deliberately not a link — there is nothing on the other
    side of it."""
    from app.models import Entity, EntityTag

    entity = Entity(value="1.2.3.4", entity_type="ip_address")
    async_db.add(entity)
    await async_db.commit()
    await async_db.refresh(entity)
    async_db.add(EntityTag(entity_id=entity.id, tag="both-sides", color="red"))
    await async_db.commit()

    await _login(test_client, "other@jt.example.com")
    await test_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "both-sides"})
    await test_client.post(f"/jobs/{data['public'].id}/tags", data={"tag": "jobs-only"})

    body = (await test_client.get("/intel/tags")).text

    assert "/intel?tags=both-sides" in body, "pivot to the entity list"
    assert "/jobs?tags=both-sides" in body, "pivot to the jobs list"
    # `jobs-only` has no entities, so its Entities cell is a plain 0 rather than a link.
    assert "/intel?tags=jobs-only" not in body


async def test_the_manager_job_count_is_visibility_filtered(test_client, async_db, data):
    """It is a link, so an over-count lands the reader on a shorter list with no explanation."""
    from app.models import JobTag

    async_db.add(JobTag(job_id=data["private"].id, tag="shared-name", color="gray"))
    async_db.add(JobTag(job_id=data["public"].id, tag="shared-name", color="gray"))
    await async_db.commit()

    await _login(test_client, "other@jt.example.com")  # cannot see bob's private job
    body = (await test_client.get("/intel/tags")).text

    row = body[body.index("shared-name") :][:1200]
    assert ">1</a>" in row, "the private job must not be counted"


async def test_tags_are_reachable_from_the_top_level_nav(test_client, async_db, data):
    """One destination, linked where you can always see it — not a tab inside one of the two
    surfaces it labels."""
    await _login(test_client, "other@jt.example.com")
    body = (await test_client.get("/jobs")).text
    assert 'href="/intel/tags"' in body, "the nav must offer the manager"


async def test_the_jobs_page_no_longer_carries_a_tags_tab(test_client, async_db, data):
    """It showed a subset of what the nav destination shows — the split the unification
    removed."""
    await _login(test_client, "other@jt.example.com")
    body = (await test_client.get("/jobs")).text
    assert "loadJobTags" not in body
    assert (await test_client.get("/jobs/tags")).status_code in (404, 422)


async def test_watching_lists_only_your_own_subscriptions(test_client, async_db, data):
    """Owner-only for an admin too — the divergence from watch *rules*, where an admin sees
    every one."""
    from app import job_watch

    await job_watch.ensure_watch_async(async_db, data["public"].id, data["other"].id)
    await async_db.commit()

    await _login(test_client, "admin@jt.example.com")
    body = (await test_client.get("/jobs/watching", headers={"HX-Request": "true"})).text
    assert "You are not watching any jobs" in body, "an admin sees their own watches, not everyone's"


async def test_stop_watching_from_the_pane(test_client, async_db, data):
    from app import job_watch
    from app.models import JobWatch

    await _login(test_client, "other@jt.example.com")
    await test_client.post(f"/jobs/{data['public'].id}/watch")

    resp = await test_client.post(f"/jobs/watching/{data['public'].id}/stop")
    assert resp.status_code == 200
    assert "You are not watching any jobs" in resp.text
    assert (await async_db.execute(select(JobWatch))).scalars().all() == []
    assert job_watch  # imported for the fixture's sake


async def test_the_watching_badge_is_swapped_out_of_band(test_client, async_db, data):
    """Mark read changes the unread count while swapping only the pane, so the tab badge
    would sit stale until reload. Rendered even at zero — 1 -> 0 is the case that needs a
    target to swap into."""
    from app import job_watch

    await job_watch.ensure_watch_async(async_db, data["public"].id, data["other"].id)
    await async_db.commit()
    await job_watch.record_events_async(async_db, kind="comment", job_id=data["public"].id, ref_id=1, actor_user_id=data["owner"].id)
    await async_db.commit()

    await _login(test_client, "other@jt.example.com")
    body = (await test_client.get("/jobs/watching", headers={"HX-Request": "true"})).text
    assert 'id="tab-badge-watching"' in body
    assert "hx-swap-oob" in body

    acked = (await test_client.post(f"/jobs/watching/{data['public'].id}/ack")).text
    assert 'id="tab-badge-watching"' in acked, "the badge must still be swappable at zero"
