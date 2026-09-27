"""Several tags in one submission, everywhere a tag can be applied.

One tag per submission would mean three round trips to label three things, through a
control that closes itself after each one.

The parsing half is Tier 1 and is most of the risk, because every rule it enforces applies
to all six write routes at once:

* a comma is a separator — `normalize_tag("a,b")` alone would store the literal tag `a,b`,
  which is the single most obvious thing to type into a tag box;
* colours are per tag, because a tag name carries one colour instance-wide and one colour
  for the whole submission would repaint every existing tag picked into it;
* no name is reserved — a built-in label is an ordinary tag a rule applies.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import AnalysisJob, Entity, EntityTag, JobStatus, JobTag, LogFile, TagDefinition, User, WorkflowDef
from app.tags import TAG_WRITE_MAX, parse_tag_write

pytestmark = pytest.mark.anyio


# ── Tier 1: the parser ──────────────────────────────────────────────────────────────────


class TestParseTagWrite:
    def test_one_tag_and_one_colour_is_unchanged(self):
        """Every caller that predates the multi-value picker sends exactly this."""
        assert parse_tag_write("apt29", "red") == [("apt29", "red")]

    def test_a_comma_separates(self):
        assert parse_tag_write("apt29,c2,triage") == [("apt29", "gray"), ("c2", "gray"), ("triage", "gray")]

    def test_colours_are_index_aligned(self):
        assert parse_tag_write("a,b", "red,blue") == [("a", "red"), ("b", "blue")]

    def test_one_colour_applies_to_all_of_them(self):
        """`?tag=a,b,c&color=red` reads as "all of them red", and a caller sending a single
        colour means exactly that — not "red, then default"."""
        assert parse_tag_write("a,b,c", "red") == [("a", "red"), ("b", "red"), ("c", "red")]

    def test_normalization_matches_the_read_path(self):
        """`tag:` queries normalize the same way, so a tag written differently is a tag that
        cannot be found."""
        assert parse_tag_write("  APT29 ") == [("apt29", "gray")]

    def test_blanks_and_duplicates_drop_out(self):
        assert parse_tag_write("a,,a, ,b") == [("a", "gray"), ("b", "gray")]

    def test_an_unknown_colour_degrades_to_gray(self):
        assert parse_tag_write("a", "chartreuse") == [("a", "gray")]

    def test_no_name_is_reserved_any_more(self):
        """`lolbin` is an ordinary tag that an ordinary built-in rule applies, so an analyst
        may type it — and if the rule already did,
        `uq_entity_tag` makes the second write a no-op rather than a conflict.
        """
        assert parse_tag_write("lolbin,ok") == [("lolbin", "gray"), ("ok", "gray")]

    def test_it_is_capped(self):
        assert len(parse_tag_write(",".join(f"t{i}" for i in range(TAG_WRITE_MAX + 5)))) == TAG_WRITE_MAX

    def test_empty_input_yields_nothing(self):
        assert parse_tag_write("") == []
        assert parse_tag_write(" , , ") == []


# ── Tier 3: the write routes ────────────────────────────────────────────────────────────


async def _user(async_db, *, email: str, role: str = "member", superuser: bool = False) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    return await UserManager(user_db).create(UserCreate(email=email, password="pass123456", is_superuser=superuser, is_active=True, role=role))


@pytest.fixture()
async def data(async_db):
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="a.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    async_db.add(Entity(id=1, value="svchost.exe", entity_type="executable"))
    async_db.add(Entity(id=2, value="10.0.0.5", entity_type="ip_address"))
    await async_db.commit()
    await _user(async_db, email="m@multi.example.com")
    jobs = [AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False) for _ in range(2)]
    async_db.add_all(jobs)
    await async_db.commit()
    for j in jobs:
        await async_db.refresh(j)
    return {"jobs": jobs}


async def _login(client) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": "m@multi.example.com", "password": "pass123456"})
    assert resp.status_code in (200, 204)


class TestOneSubmissionSeveralTags:
    async def test_a_job_takes_several_tags_at_once(self, test_client, async_db, data):
        await _login(test_client)
        job = data["jobs"][0]
        resp = await test_client.post(f"/jobs/{job.id}/tags", data={"tag": "apt29,c2,triage", "color": "red,blue"})
        assert resp.status_code == 200

        rows = (await async_db.execute(select(JobTag).where(JobTag.job_id == job.id))).scalars().all()
        assert sorted(r.tag for r in rows) == ["apt29", "c2", "triage"]
        # Each keeps the colour it was submitted with — one colour for the field would have
        # repainted all three.
        assert {r.tag: r.color for r in rows} == {"apt29": "red", "c2": "blue", "triage": "blue"}

    async def test_every_new_name_joins_the_vocabulary(self, test_client, async_db, data):
        """Not just the first: a tag coined here must still be offered by the picker after
        its last job is deleted."""
        await _login(test_client)
        await test_client.post(f"/jobs/{data['jobs'][0].id}/tags", data={"tag": "alpha,beta", "color": "green"})
        defined = (await async_db.execute(select(TagDefinition.tag))).scalars().all()
        assert {"alpha", "beta"} <= set(defined)

    async def test_an_entity_takes_several_tags_at_once(self, test_client, async_db, data):
        await _login(test_client)
        resp = await test_client.post("/intel/entities/1/tags", data={"tag": "apt29,c2", "color": "red,blue"})
        assert resp.status_code == 200
        rows = (await async_db.execute(select(EntityTag).where(EntityTag.entity_id == 1))).scalars().all()
        assert sorted(r.tag for r in rows) == ["apt29", "c2"]

    async def test_bulk_tagging_applies_every_tag_to_every_job(self, test_client, async_db, data):
        await _login(test_client)
        ids = ",".join(str(j.id) for j in data["jobs"])
        resp = await test_client.post("/jobs/bulk-tag", data={"job_ids": ids, "tag": "sweep,reviewed", "color": "amber"})
        assert resp.status_code == 200
        rows = (await async_db.execute(select(JobTag))).scalars().all()
        assert len(rows) == 4, "two tags on two jobs"
        # It reports JOBS touched, not rows written: "tagged 4 jobs" would name more jobs
        # than were selected.
        assert "2 jobs" in resp.text

    async def test_bulk_untagging_removes_every_named_tag(self, test_client, async_db, data):
        await _login(test_client)
        ids = ",".join(str(j.id) for j in data["jobs"])
        await test_client.post("/jobs/bulk-tag", data={"job_ids": ids, "tag": "sweep,reviewed,keep"})
        await test_client.post("/jobs/bulk-untag", data={"job_ids": ids, "tag": "sweep,reviewed"})
        rows = (await async_db.execute(select(JobTag))).scalars().all()
        assert sorted({r.tag for r in rows}) == ["keep"]

    async def test_a_built_in_label_name_is_now_writable_by_hand(self, test_client, async_db, data):
        """Labels are rules that write tags, so `lolbin` is simply a tag — one a built-in
        rule also applies. Refusing it would mean an analyst
        cannot label by hand what the instance labels automatically, which is the opposite
        of making the vocabulary editable.
        """
        await _login(test_client)
        resp = await test_client.post("/intel/entities/1/tags", data={"tag": "lolbin"})
        assert resp.status_code == 200
        rows = (await async_db.execute(select(EntityTag).where(EntityTag.entity_id == 1))).scalars().all()
        assert [r.tag for r in rows] == ["lolbin"]

    async def test_it_lands_beside_the_others_in_one_submission(self, test_client, async_db, data):
        await _login(test_client)
        resp = await test_client.post("/intel/entities/1/tags", data={"tag": "lolbin,fine"})
        assert resp.status_code == 200
        rows = (await async_db.execute(select(EntityTag).where(EntityTag.entity_id == 1))).scalars().all()
        assert sorted(r.tag for r in rows) == ["fine", "lolbin"]

    async def test_one_bell_event_per_submission_not_per_tag(self, test_client, async_db, data):
        """Three tags from one click is one thing that happened. Three bell entries is the
        noise that teaches people to ignore the bell."""
        from app.models import JobWatch, JobWatchEvent

        watcher = await _user(async_db, email="w@multi.example.com")
        job = data["jobs"][0]
        async_db.add(JobWatch(job_id=job.id, user_id=watcher.id))
        await async_db.commit()

        await _login(test_client)
        await test_client.post(f"/jobs/{job.id}/tags", data={"tag": "a,b,c"})
        events = (await async_db.execute(select(JobWatchEvent).where(JobWatchEvent.kind == "tag"))).scalars().all()
        assert len(events) == 1
        assert "a, b, c" in events[0].summary


class TestWatchRuleAutoTag:
    """A rule can auto-apply several tags, and stops repainting the ones that exist."""

    async def test_a_rule_stores_and_reapplies_a_list(self, test_client, async_db, data):
        from app.models import IntelRule

        await _login(test_client)
        resp = await test_client.post(
            "/intel/rules",
            data={"name": "lolbins", "query": "label:lolbin", "action_tag": "auto,triage", "action_tag_color": "red,blue"},
        )
        assert resp.status_code in (200, 303)
        rule = (await async_db.execute(select(IntelRule).where(IntelRule.name == "lolbins"))).scalar_one()
        assert rule.action_tag == "auto,triage"
        assert rule.action_tag_color == "red,blue"

    async def test_a_rule_may_auto_tag_with_a_built_in_name_too(self, test_client, async_db, data):
        """Which is how the built-in rules themselves work — `parse_tag_write` is their
        parser as much as the picker's, so a refusal here would have made them unseedable."""
        from app.models import IntelRule

        await _login(test_client)
        await test_client.post("/intel/rules", data={"name": "r2", "query": "type:user", "action_tag": "lolbin,fine"})
        rule = (await async_db.execute(select(IntelRule).where(IntelRule.name == "r2"))).scalar_one()
        assert rule.action_tag == "lolbin,fine"

    def test_apply_tag_writes_every_tag(self, sync_db):
        """The worker half, which is sync and cannot reuse the async helpers."""
        from app.intel.rules import _apply_tag
        from app.models import Entity as E
        from app.models import IntelRule

        ent = E(value="cmd.exe", entity_type="executable")
        sync_db.add(ent)
        sync_db.commit()
        sync_db.refresh(ent)

        rule = IntelRule(name="r", query="", action_tag="alpha,beta", action_tag_color="red,blue")
        assert _apply_tag(sync_db, rule, [ent]) == 2
        rows = sync_db.execute(select(EntityTag).where(EntityTag.entity_id == ent.id)).scalars().all()
        assert {r.tag: r.color for r in rows} == {"alpha": "red", "beta": "blue"}

    def test_it_does_not_repaint_a_tag_that_already_has_a_colour(self, sync_db):
        """Stamping the rule's colour onto existing tags would be the same instance-wide
        repaint the manual path deliberately avoids, arriving one entity at a time."""
        from app.intel.rules import _apply_tag
        from app.models import Entity as E
        from app.models import IntelRule

        ent = E(value="10.0.0.9", entity_type="ip_address")
        sync_db.add_all([ent, TagDefinition(tag="known", color="purple")])
        sync_db.commit()
        sync_db.refresh(ent)

        rule = IntelRule(name="r", query="", action_tag="known", action_tag_color="red")
        assert _apply_tag(sync_db, rule, [ent]) == 1
        row = sync_db.execute(select(EntityTag).where(EntityTag.entity_id == ent.id)).scalar_one()
        assert row.color == "purple", "the vocabulary's colour wins over the rule's swatch"
