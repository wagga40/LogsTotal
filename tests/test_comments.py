"""Route + model tests for discussion threads on cases, entities, and jobs.

The interesting surface is authorization: three targets with three different audiences,
plus a private-job boundary the thread must not cross.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.comments import comment_counts_for
from app.models import (
    AnalysisJob,
    Comment,
    Entity,
    EntityJobLink,
    InvestigationCase,
    JobStatus,
    LogFile,
    User,
    WorkflowDef,
)

pytestmark = pytest.mark.anyio


async def _create_user(async_db, *, email: str, role: str = "member", is_superuser: bool = False) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=is_superuser, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


@pytest.fixture()
async def base_rows(async_db):
    """A public job, a private job (owned by `owner`), an entity, and a shared case."""
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    await async_db.commit()

    owner = await _create_user(async_db, email="owner@c.example.com")
    other = await _create_user(async_db, email="other@c.example.com")
    basic = await _create_user(async_db, email="basic@c.example.com", role="user")
    admin = await _create_user(async_db, email="admin@c.example.com", role="admin", is_superuser=True)

    public_job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    private_job = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner.id)
    entity = Entity(value="10.0.0.1", entity_type="ip_address", job_count=1)
    async_db.add_all([public_job, private_job, entity])
    await async_db.commit()

    case = InvestigationCase(name="Shared Case", created_by_user_id=owner.id, is_shared=True)
    private_case = InvestigationCase(name="Private Case", created_by_user_id=owner.id, is_shared=False)
    async_db.add_all([case, private_case])
    await async_db.commit()

    for obj in (public_job, private_job, entity, case, private_case, owner, other, basic, admin):
        await async_db.refresh(obj)
    return {
        "public_job": public_job,
        "private_job": private_job,
        "entity": entity,
        "case": case,
        "private_case": private_case,
        "owner": owner,
        "other": other,
        "basic": basic,
        "admin": admin,
    }


def _post(client, target_type, target_id, body):
    return client.post(f"/comments/{target_type}/{target_id}", data={"body": body})


# ── Posting and reading ──────────────────────────────────────────────────────


async def test_member_posts_and_reads_case_comment(test_client, base_rows):
    case = base_rows["case"]
    await _login(test_client, "owner@c.example.com")

    resp = await _post(test_client, "case", case.id, "Lateral movement confirmed.")
    assert resp.status_code == 200
    assert "Lateral movement confirmed." in resp.text

    thread = await test_client.get(f"/comments/case/{case.id}")
    assert "Lateral movement confirmed." in thread.text
    assert "owner@c.example.com" in thread.text


async def test_empty_body_is_a_noop_not_an_error(test_client, async_db, base_rows):
    case = base_rows["case"]
    await _login(test_client, "owner@c.example.com")
    resp = await _post(test_client, "case", case.id, "   ")
    assert resp.status_code == 200
    assert (await async_db.execute(select(Comment))).scalars().all() == []


async def test_body_over_cap_rejected(test_client, base_rows):
    await _login(test_client, "owner@c.example.com")
    assert (await _post(test_client, "case", base_rows["case"].id, "x" * 4001)).status_code == 400
    assert (await _post(test_client, "case", base_rows["case"].id, "x" * 4000)).status_code == 200


async def test_thread_caps_at_page_size_and_reports_total(test_client, async_db, base_rows, monkeypatch):
    """Only the newest page renders, but the header still reports the true count."""
    import app.comments as comments_mod

    monkeypatch.setattr(comments_mod, "THREAD_PAGE", 3)
    case, owner = base_rows["case"], base_rows["owner"]
    for i in range(5):
        async_db.add(Comment(case_id=case.id, author_user_id=owner.id, body=f"msg {i}"))
    await async_db.commit()

    await _login(test_client, "owner@c.example.com")
    text = (await test_client.get(f"/comments/case/{case.id}")).text
    assert "showing the latest 3 of 5" in text
    assert "msg 0" not in text and "msg 4" in text


# ── Per-target authorization ─────────────────────────────────────────────────


async def test_entity_thread_requires_member(test_client, base_rows):
    entity = base_rows["entity"]
    await _login(test_client, "basic@c.example.com")
    assert (await test_client.get(f"/comments/entity/{entity.id}")).status_code == 403
    assert (await _post(test_client, "entity", entity.id, "nope")).status_code == 403


async def test_job_thread_allows_plain_user(test_client, base_rows):
    """The one place a non-member may write: a job they can already view."""
    job = base_rows["public_job"]
    await _login(test_client, "basic@c.example.com")
    resp = await _post(test_client, "job", job.id, "Looks like a false positive.")
    assert resp.status_code == 200
    assert "Looks like a false positive." in resp.text


async def test_job_thread_rejects_anonymous(test_client, base_rows):
    job = base_rows["public_job"]
    assert (await test_client.get(f"/comments/job/{job.id}")).status_code == 401
    assert (await _post(test_client, "job", job.id, "hi")).status_code == 401


async def test_job_page_shows_comments_region_only_for_logged_in(test_client, base_rows):
    job = base_rows["public_job"]
    assert "job-comments-region" not in (await test_client.get(f"/jobs/{job.id}")).text

    await _login(test_client, "basic@c.example.com")
    assert "job-comments-region" in (await test_client.get(f"/jobs/{job.id}")).text


async def test_comments_region_never_enters_the_polling_partial(test_client, base_rows):
    """The card must sit outside #job-status-region, which morph-swaps every 3s."""
    job = base_rows["public_job"]
    await _login(test_client, "basic@c.example.com")
    partial = await test_client.get(f"/jobs/{job.id}/status-partial")
    assert "job-comments-region" not in partial.text


async def test_unshared_case_thread_is_404_for_other_members(test_client, base_rows):
    private_case = base_rows["private_case"]
    await _login(test_client, "other@c.example.com")
    assert (await test_client.get(f"/comments/case/{private_case.id}")).status_code == 404
    assert (await _post(test_client, "case", private_case.id, "peek")).status_code == 404


async def test_unknown_target_type_is_404(test_client, base_rows):
    await _login(test_client, "owner@c.example.com")
    assert (await test_client.get("/comments/workflow/1")).status_code == 404


# ── Private-job isolation ────────────────────────────────────────────────────


async def test_private_job_thread_hidden_from_non_owner(test_client, async_db, base_rows):
    job, owner = base_rows["private_job"], base_rows["owner"]
    async_db.add(Comment(job_id=job.id, author_user_id=owner.id, body="internal only"))
    await async_db.commit()

    await _login(test_client, "other@c.example.com")
    assert (await test_client.get(f"/comments/job/{job.id}")).status_code == 404
    assert (await _post(test_client, "job", job.id, "sneak")).status_code == 404

    await _login(test_client, "owner@c.example.com")
    assert "internal only" in (await test_client.get(f"/comments/job/{job.id}")).text

    await _login(test_client, "admin@c.example.com")
    assert "internal only" in (await test_client.get(f"/comments/job/{job.id}")).text


# ── Edit and delete ──────────────────────────────────────────────────────────


async def test_only_author_can_edit(test_client, async_db, base_rows):
    case, owner = base_rows["case"], base_rows["owner"]
    comment = Comment(case_id=case.id, author_user_id=owner.id, body="original")
    async_db.add(comment)
    await async_db.commit()
    await async_db.refresh(comment)

    await _login(test_client, "other@c.example.com")
    assert (await test_client.post(f"/comments/{comment.id}/edit", data={"body": "hijacked"})).status_code == 403

    # Not even an admin may rewrite someone else's words.
    await _login(test_client, "admin@c.example.com")
    assert (await test_client.post(f"/comments/{comment.id}/edit", data={"body": "hijacked"})).status_code == 403

    await _login(test_client, "owner@c.example.com")
    resp = await test_client.post(f"/comments/{comment.id}/edit", data={"body": "revised"})
    assert resp.status_code == 200
    assert "revised" in resp.text and "edited" in resp.text

    await async_db.refresh(comment)
    assert comment.body == "revised"
    assert comment.edited_at is not None


async def test_case_owner_and_admin_can_delete_others_comments(test_client, async_db, base_rows):
    case = base_rows["case"]
    by_other = Comment(case_id=case.id, author_user_id=base_rows["other"].id, body="from other")
    for_admin = Comment(case_id=case.id, author_user_id=base_rows["other"].id, body="for admin")
    async_db.add_all([by_other, for_admin])
    await async_db.commit()
    await async_db.refresh(by_other)
    await async_db.refresh(for_admin)

    await _login(test_client, "owner@c.example.com")  # case owner, not the author
    assert (await test_client.post(f"/comments/{by_other.id}/delete")).status_code == 200

    await _login(test_client, "admin@c.example.com")
    assert (await test_client.post(f"/comments/{for_admin.id}/delete")).status_code == 200


async def test_uninvolved_member_cannot_delete(test_client, async_db, base_rows):
    case = base_rows["case"]
    third = await _create_user(async_db, email="third@c.example.com")
    comment = Comment(case_id=case.id, author_user_id=base_rows["owner"].id, body="mine")
    async_db.add(comment)
    await async_db.commit()
    await async_db.refresh(comment)

    await _login(test_client, "third@c.example.com")
    assert (await test_client.post(f"/comments/{comment.id}/delete")).status_code == 403
    _ = third


async def test_delete_blanks_body_and_hides_from_thread_and_counts(test_client, async_db, base_rows):
    case, owner = base_rows["case"], base_rows["owner"]
    comment = Comment(case_id=case.id, author_user_id=owner.id, body="secret payload path")
    async_db.add(comment)
    await async_db.commit()
    await async_db.refresh(comment)

    await _login(test_client, "owner@c.example.com")
    resp = await test_client.post(f"/comments/{comment.id}/delete")
    assert resp.status_code == 200
    assert "secret payload path" not in resp.text

    await async_db.refresh(comment)
    assert comment.deleted_at is not None
    assert comment.deleted_by_user_id == owner.id
    assert comment.body == "", "the text must actually be gone, not just hidden"

    assert await comment_counts_for(async_db, "case", [case.id]) == {}
    assert (await test_client.post(f"/comments/{comment.id}/delete")).status_code == 404


# ── Tab badges ───────────────────────────────────────────────────────────────


async def test_discussion_tab_badge_counts_comments_not_characters(async_db, base_rows):
    """A badge of len(entity.notes) would read "1500" for a 1,500-char note. The tab is
    "Discussions" and holds only the thread — the note lives on Overview — which makes a
    character count doubly wrong."""
    from app.routers.intel import _build_entity_tabs

    entity = base_rows["entity"]
    entity.notes = "x" * 1500
    await async_db.commit()

    tab = next(t for t in _build_entity_tabs(entity, 0, 0, comment_count=2) if t["key"] == "discussion")
    assert tab["badge"] == 2
    assert tab["label"] == "Discussions"
    assert tab["lazy_event"] == "loadComments"

    empty_tab = next(t for t in _build_entity_tabs(entity, 0, 0, comment_count=0) if t["key"] == "discussion")
    assert empty_tab["badge"] is None


# ── Deletion cascades ────────────────────────────────────────────────────────


async def test_case_delete_removes_its_comments(test_client, async_db, base_rows):
    case, owner = base_rows["case"], base_rows["owner"]
    async_db.add(Comment(case_id=case.id, author_user_id=owner.id, body="bye"))
    await async_db.commit()

    await _login(test_client, "owner@c.example.com")
    resp = await test_client.post(f"/intel/cases/{case.id}/delete", follow_redirects=False)
    assert resp.status_code in (200, 303)
    assert (await async_db.execute(select(Comment).where(Comment.case_id == case.id))).scalars().all() == []


async def test_job_delete_removes_comments(test_client, async_db, base_rows, fake_redis):
    job, owner = base_rows["public_job"], base_rows["owner"]
    async_db.add(Comment(job_id=job.id, author_user_id=owner.id, body="bye"))
    await async_db.commit()

    await _login(test_client, "admin@c.example.com")
    resp = await test_client.post(f"/jobs/{job.id}/delete", follow_redirects=False)
    assert resp.status_code in (200, 303)
    assert (await async_db.execute(select(Comment).where(Comment.job_id == job.id))).scalars().all() == []


async def test_entity_orphan_cleanup_removes_comments(async_db, base_rows):
    """`remove_entity_links_for_job_async` deletes orphans via Core delete() — no ORM
    cascade fires, so Comment rows must be dropped explicitly or PostgreSQL FK-errors."""
    from app.intel.entities import remove_entity_links_for_job_async

    job, entity, owner = base_rows["public_job"], base_rows["entity"], base_rows["owner"]
    async_db.add(EntityJobLink(entity_id=entity.id, job_id=job.id))
    async_db.add(Comment(entity_id=entity.id, author_user_id=owner.id, body="on an orphan"))
    await async_db.commit()

    await remove_entity_links_for_job_async(async_db, job.id)
    await async_db.commit()

    assert await async_db.get(Entity, entity.id) is None
    assert (await async_db.execute(select(Comment).where(Comment.entity_id == entity.id))).scalars().all() == []


# ── Job page tabs ────────────────────────────────────────────────────────────


async def test_job_page_has_results_and_discussion_tabs_for_logged_in(test_client, base_rows):
    job = base_rows["public_job"]
    await _login(test_client, "basic@c.example.com")
    body = (await test_client.get(f"/jobs/{job.id}")).text
    assert "resourceTabs(" in body
    assert "select('results')" in body
    assert "select('discussion')" in body


async def test_job_page_has_no_tab_strip_for_anonymous(test_client, base_rows):
    """A single-tab strip would be noise — anonymous users just get the results."""
    job = base_rows["public_job"]
    body = (await test_client.get(f"/jobs/{job.id}")).text
    assert "resourceTabs(" not in body
    assert "job-status-region" in body, "results must still render without tabs"


async def test_discussion_tab_badge_counts_comments(test_client, async_db, base_rows):
    job, owner = base_rows["public_job"], base_rows["owner"]
    async_db.add_all([Comment(job_id=job.id, author_user_id=owner.id, body=f"m{i}") for i in range(3)])
    await async_db.commit()

    await _login(test_client, "owner@c.example.com")
    from app.routers.jobs import _build_job_tabs

    tabs = _build_job_tabs(base_rows["owner"], 3)
    discussion = next(t for t in tabs if t["key"] == "discussion")
    assert discussion["badge"] == 3
    assert discussion["lazy_event"] == "loadComments"

    # The claim is "anonymous gets exactly one tab, and it is Results with nothing on it" —
    # asserted field by field rather than as a whole-dict equality, so adding a presentational
    # key (an icon) is not a failing test.
    solo = _build_job_tabs(None, 0)
    assert len(solo) == 1
    assert (solo[0]["key"], solo[0]["label"], solo[0]["badge"], solo[0]["lazy_event"]) == ("results", "Results", None, None)


async def test_discussion_pane_is_lazy_and_outside_the_poll_region(test_client, base_rows):
    """Still the hard requirement: the thread must never be inside #job-status-region."""
    job = base_rows["public_job"]
    await _login(test_client, "basic@c.example.com")
    body = (await test_client.get(f"/jobs/{job.id}")).text
    assert 'hx-trigger="loadComments from:body once"' in body
    # The comments region must come *after* the status region closes, never nested in it.
    assert "job-comments-region" not in (await test_client.get(f"/jobs/{job.id}/status-partial")).text


async def test_orphan_cleanup_clears_every_table_referencing_entity(async_db, base_rows):
    """Orphaned entities must not leave dangling case links / tags / rule alerts.

    SQLite does not enforce foreign keys by default, so this would corrupt silently (a case
    reporting N entities whose rows no longer exist); PostgreSQL would raise
    ForeignKeyViolation and fail the job deletion outright.
    """
    from sqlalchemy import func

    from app.intel.entities import remove_entity_links_for_job_async
    from app.models import CaseEntityLink, EntityTag, FindingEntityLink

    job, entity, case, owner = base_rows["public_job"], base_rows["entity"], base_rows["case"], base_rows["owner"]
    async_db.add_all(
        [
            EntityJobLink(entity_id=entity.id, job_id=job.id),
            CaseEntityLink(case_id=case.id, entity_id=entity.id, added_by_user_id=owner.id),
            EntityTag(entity_id=entity.id, tag="doomed", color="red"),
            Comment(entity_id=entity.id, author_user_id=owner.id, body="note on a doomed entity"),
        ]
    )
    await async_db.commit()

    await remove_entity_links_for_job_async(async_db, job.id)
    await async_db.commit()

    assert await async_db.get(Entity, entity.id) is None
    for model in (CaseEntityLink, EntityTag, FindingEntityLink, Comment):
        left = await async_db.scalar(select(func.count()).select_from(model).where(model.entity_id == entity.id))
        assert left == 0, f"{model.__name__} rows left dangling after the entity was deleted"


def test_orphan_cleanup_covers_every_fk_to_entity():
    """The cleanup must name every table referencing `entity`, derived from the metadata.

    `remove_entity_links_for_job_async` uses Core `delete()`, so no ORM cascade fires and
    each referencing table has to be cleared by hand. The test above hardcodes the tables
    it seeds, which means a *newly added* FK — the exact drift this guard exists to catch —
    would slip past it. Reading `Base.metadata` instead makes the check self-maintaining.
    """
    import inspect as _inspect

    from app.database import Base
    from app.intel import entities as entities_mod

    referencing = {table.name for table in Base.metadata.tables.values() for col in table.columns for fk in col.foreign_keys if fk.column.table.name == "entity"}
    assert referencing, "expected at least one table with a FK to entity"

    source = _inspect.getsource(entities_mod.remove_entity_links_for_job_async)
    by_table = {t.name: cls for cls in Base.registry.mappers for t in [cls.local_table] if t is not None}

    missing = sorted(name for name in referencing if (by_table[name].class_.__name__ if name in by_table else name) not in source)
    assert not missing, f"remove_entity_links_for_job_async does not delete from: {missing} (dangling rows on SQLite, ForeignKeyViolation on PostgreSQL)"


# ── Notes and Discussions are separate things ────────────────────────────────


async def test_the_entity_note_lives_on_overview_and_the_thread_has_its_own_tab(test_client, base_rows):
    """One field describing the entity and a multi-party conversation do not share a tab.
    The note is prose about the entity, so it belongs with the rest of the
    entity; the thread is a conversation, so it gets the tab and the count."""
    entity = base_rows["entity"]
    await _login(test_client, "other@c.example.com")

    body = (await test_client.get(f"/intel/entities/{entity.id}")).text

    # The editor is in the Overview pane, not behind a tab of its own.
    assert 'id="entity-notes-region"' in body
    assert '"key": "discussion"' in body
    assert '"label": "Discussions"' in body
    assert '"key": "notes"' not in body

    # The thread waits for the tab instead of loading with the page.
    assert f'hx-get="/comments/entity/{entity.id}"' in body
    assert 'hx-trigger="loadComments from:body once"' in body


async def test_the_case_narrative_lives_on_overview_and_the_thread_has_its_own_tab(test_client, base_rows):
    case = base_rows["case"]
    await _login(test_client, "owner@c.example.com")

    body = (await test_client.get(f"/intel/cases/{case.id}")).text

    assert 'id="case-notes-region"' in body
    assert '"key": "discussion"' in body
    assert '"key": "notes"' not in body
    assert 'hx-trigger="loadComments from:body once"' in body


async def test_the_entity_note_still_saves_and_clears(test_client, base_rows):
    """The edit form moved into the partial, so its swap target moved with it. If those two
    ever disagree the Save button silently does nothing visible."""
    entity = base_rows["entity"]
    await _login(test_client, "other@c.example.com")

    saved = await test_client.post(f"/intel/entities/{entity.id}/notes", data={"body": "beaconing every 60s"})
    assert saved.status_code == 200
    assert "beaconing every 60s" in saved.text
    assert 'id="entity-notes-region"' in saved.text, "the response must replace the region it targets"

    cleared = await test_client.post(f"/intel/entities/{entity.id}/notes", data={"body": ""})
    assert "No analyst notes yet." in cleared.text


# ── the tab badge keeps up with the thread ───────────────────────────────────


async def test_posting_updates_the_tab_badge_without_a_reload(test_client, base_rows):
    """The badge is server-rendered once, at page load, and posting swaps only the thread —
    so on its own the count would sit stale until a reload. The thread response carries an
    out-of-band span addressed at the tab strip."""
    entity = base_rows["entity"]
    await _login(test_client, "other@c.example.com")

    first = await _post(test_client, "entity", entity.id, "one")
    assert 'id="tab-badge-discussion"' in first.text
    assert 'hx-swap-oob="true"' in first.text
    assert ">1</span>" in first.text

    second = await _post(test_client, "entity", entity.id, "two")
    assert ">2</span>" in second.text


async def test_the_badge_target_exists_even_at_zero(test_client, base_rows):
    """0 -> 1 is the case that could not work before: a badge rendered only when non-zero
    gives htmx nothing to swap into on the very first comment."""
    entity = base_rows["entity"]
    await _login(test_client, "other@c.example.com")

    body = (await test_client.get(f"/intel/entities/{entity.id}")).text
    assert 'id="tab-badge-discussion"' in body
    assert "hidden" in body.split('id="tab-badge-discussion"')[1][:200]


async def test_deleting_takes_the_badge_back_down(test_client, async_db, base_rows):
    """Edits and deletes go through the same _render_thread, so the count self-corrects."""
    from sqlalchemy import select as _select

    entity = base_rows["entity"]
    await _login(test_client, "other@c.example.com")
    await _post(test_client, "entity", entity.id, "temporary")

    comment = (await async_db.execute(_select(Comment).where(Comment.entity_id == entity.id))).scalars().first()
    resp = await test_client.post(f"/comments/{comment.id}/delete")
    assert resp.status_code == 200
    # Back to zero: the span comes back empty and hidden rather than vanishing.
    oob = resp.text.split('id="tab-badge-discussion"')[1][:200]
    assert "hidden" in oob
    assert ">0<" not in oob
