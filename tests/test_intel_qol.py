"""Route tests for the Intel/job QoL fixes: watchlist ack-all, entity-note cap,
tag recolor, and the "in these cases" backlinks on entity/job detail."""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
    CaseEntityLink,
    CaseJobLink,
    Entity,
    EntityTag,
    InvestigationCase,
    JobStatus,
    LogFile,
    User,
    WorkflowDef,
)

pytestmark = pytest.mark.anyio


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


@pytest.fixture()
async def entity(async_db) -> Entity:
    ent = Entity(value="10.1.2.3", entity_type="ip_address", job_count=1)
    async_db.add(ent)
    await async_db.commit()
    await async_db.refresh(ent)
    return ent


@pytest.fixture()
async def job(async_db) -> AnalysisJob:
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    j = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED)
    async_db.add(j)
    await async_db.commit()
    await async_db.refresh(j)
    return j


# ── Watchlist ack-all ────────────────────────────────────────────────────────


async def test_ack_all_returns_dropdown_and_is_idempotent(member_client, async_db, member_user, entity, job, fake_redis):
    """The acks commit and the route returns — no TypeError after the commit from a
    keyword the callee does not take.

    The bell reads `intel_rule_match`. Acknowledging is per user because a match belongs to
    one rule, which belongs to one person.
    """
    from app.models import IntelRule, IntelRuleMatch

    rule = IntelRule(name="mine", owner_user_id=member_user.id, query=entity.value)
    async_db.add(rule)
    await async_db.flush()
    async_db.add(IntelRuleMatch(rule_id=rule.id, entity_id=entity.id, job_id=job.id))
    await async_db.commit()

    assert (await member_client.get("/intel/watchlist-events-partial?count_only=1")).text == "1"

    resp = await member_client.post("/intel/watchlist-events/ack-all")
    assert resp.status_code == 200

    remaining = (await async_db.execute(select(IntelRuleMatch).where(IntelRuleMatch.acknowledged_at.is_(None)))).scalars().all()
    assert remaining == []

    # Second call has nothing to ack and must still render.
    assert (await member_client.post("/intel/watchlist-events/ack-all")).status_code == 200


# ── Entity notes: reject over-cap instead of truncating ──────────────────────


async def test_entity_note_at_cap_is_accepted(member_client, async_db, entity):
    resp = await member_client.post(f"/intel/entities/{entity.id}/notes", data={"body": "x" * 8000})
    assert resp.status_code == 200
    await async_db.refresh(entity)
    assert len(entity.notes) == 8000


async def test_entity_note_over_cap_is_rejected(member_client, async_db, entity):
    resp = await member_client.post(f"/intel/entities/{entity.id}/notes", data={"body": "x" * 8001})
    assert resp.status_code == 400
    await async_db.refresh(entity)
    assert entity.notes is None  # nothing partially written


async def test_entity_note_empty_clears(member_client, async_db, entity):
    await member_client.post(f"/intel/entities/{entity.id}/notes", data={"body": "something"})
    resp = await member_client.post(f"/intel/entities/{entity.id}/notes", data={"body": ""})
    assert resp.status_code == 200
    await async_db.refresh(entity)
    assert entity.notes is None


# ── Tag recolor ──────────────────────────────────────────────────────────────


async def test_readding_tag_updates_color(member_client, async_db, entity):
    await member_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "apt28", "color": "gray"})
    resp = await member_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "APT28 ", "color": "red"})
    assert resp.status_code == 200

    rows = (await async_db.execute(select(EntityTag).where(EntityTag.entity_id == entity.id))).scalars().all()
    assert len(rows) == 1, "re-adding must not create a duplicate row"
    assert rows[0].tag == "apt28"
    assert rows[0].color == "red"


async def test_unknown_color_falls_back_to_gray(member_client, async_db, entity):
    await member_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "x", "color": "chartreuse"})
    row = (await async_db.execute(select(EntityTag).where(EntityTag.entity_id == entity.id))).scalar_one()
    assert row.color == "gray"


# ── Case backlinks ───────────────────────────────────────────────────────────


async def test_entity_page_shows_own_case_but_hides_another_members_unshared_case(test_client, async_db, entity):
    alice = await _create_user(async_db, email="alice@qol.example.com")
    bob = await _create_user(async_db, email="bob@qol.example.com")

    secret = InvestigationCase(name="Alice Secret Case", created_by_user_id=alice.id, is_shared=False)
    shared = InvestigationCase(name="Team Shared Case", created_by_user_id=alice.id, is_shared=True)
    async_db.add_all([secret, shared])
    await async_db.commit()
    async_db.add_all(
        [
            CaseEntityLink(case_id=secret.id, entity_id=entity.id, added_by_user_id=alice.id),
            CaseEntityLink(case_id=shared.id, entity_id=entity.id, added_by_user_id=alice.id),
        ]
    )
    await async_db.commit()

    await _login(test_client, "alice@qol.example.com")
    body = (await test_client.get(f"/intel/entities/{entity.id}")).text
    assert "Alice Secret Case" in body
    assert "Team Shared Case" in body

    await _login(test_client, "bob@qol.example.com")
    body = (await test_client.get(f"/intel/entities/{entity.id}")).text
    assert "Alice Secret Case" not in body, "unshared case name leaked to another member"
    assert "Team Shared Case" in body

    _ = bob  # created solely to own the second session


async def test_job_page_case_backlinks_hidden_from_anonymous_and_basic_user(test_client, async_db, job):
    alice = await _create_user(async_db, email="alice2@qol.example.com")
    await _create_user(async_db, email="basic@qol.example.com", role="user")

    case = InvestigationCase(name="Jobby Case", created_by_user_id=alice.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()
    async_db.add(CaseJobLink(case_id=case.id, job_id=job.id, added_by_user_id=alice.id))
    await async_db.commit()

    # Anonymous: no cookie at all.
    assert "Jobby Case" not in (await test_client.get(f"/jobs/{job.id}")).text

    await _login(test_client, "basic@qol.example.com")
    assert "Jobby Case" not in (await test_client.get(f"/jobs/{job.id}")).text, "cases leaked to a role=user viewer"

    await _login(test_client, "alice2@qol.example.com")
    assert "Jobby Case" in (await test_client.get(f"/jobs/{job.id}")).text


# ── Case graph: job_edges toggle at the route level ──────────────────────────


async def test_case_graph_job_edges_toggle_changes_payload(member_client, async_db, member_user, entity, job):
    """The Cases UI hides job edges by default; the server must actually omit them."""
    second = Entity(value="10.9.9.9", entity_type="ip_address", job_count=1)
    async_db.add(second)
    await async_db.commit()
    await async_db.refresh(second)

    case = InvestigationCase(name="Graph Case", created_by_user_id=member_user.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()
    from app.models import EntityJobLink

    async_db.add_all(
        [
            CaseEntityLink(case_id=case.id, entity_id=entity.id, added_by_user_id=member_user.id),
            CaseEntityLink(case_id=case.id, entity_id=second.id, added_by_user_id=member_user.id),
            EntityJobLink(entity_id=entity.id, job_id=job.id),
            EntityJobLink(entity_id=second.id, job_id=job.id),
        ]
    )
    await async_db.commit()

    on = (await member_client.get(f"/intel/cases/{case.id}/graph.json?job_edges=1")).json()
    assert len(on["e"]["s"]) == 1
    assert on["stats"]["job_edges"] is True

    off = (await member_client.get(f"/intel/cases/{case.id}/graph.json?job_edges=0")).json()
    assert off["e"]["s"] == []
    assert off["stats"]["job_edges"] is False

    # Default stays "on" so a bare GET keeps its historical payload.
    default = (await member_client.get(f"/intel/cases/{case.id}/graph.json")).json()
    assert len(default["e"]["s"]) == 1

    xml_on = (await member_client.get(f"/intel/cases/{case.id}/graph.graphml?job_edges=1")).text
    xml_off = (await member_client.get(f"/intel/cases/{case.id}/graph.graphml?job_edges=0")).text
    assert xml_on.count("<edge ") == 1
    assert xml_off.count("<edge ") == 0


# ── Tags as a pivot ──────────────────────────────────────────────────────────


@pytest.fixture()
async def tagged(async_db):
    """Three entities: two tagged apt28, one of those also ransomware, one untagged."""
    a = Entity(value="1.1.1.1", entity_type="ip_address", job_count=3)
    b = Entity(value="2.2.2.2", entity_type="ip_address", job_count=2)
    c = Entity(value="3.3.3.3", entity_type="ip_address", job_count=1)
    async_db.add_all([a, b, c])
    await async_db.commit()
    async_db.add_all(
        [
            EntityTag(entity_id=a.id, tag="apt28", color="red"),
            EntityTag(entity_id=a.id, tag="ransomware", color="orange"),
            EntityTag(entity_id=b.id, tag="apt28", color="red"),
        ]
    )
    await async_db.commit()
    for obj in (a, b, c):
        await async_db.refresh(obj)
    return {"a": a, "b": b, "c": c}


async def test_tags_param_filters_the_table(member_client, tagged):
    body = (await member_client.get("/intel/entities-partial?tags=apt28")).text
    assert "1.1.1.1" in body and "2.2.2.2" in body
    assert "3.3.3.3" not in body


async def test_tag_query_prefix_filters_the_table(member_client, tagged):
    body = (await member_client.get("/intel/entities-partial?q=tag:ransomware")).text
    assert "1.1.1.1" in body
    assert "2.2.2.2" not in body and "3.3.3.3" not in body


async def test_multiple_tags_are_any_of_not_all_of(member_client, tagged):
    """Clicking a second tag chip should widen the net, like the types CSV does."""
    body = (await member_client.get("/intel/entities-partial?tags=apt28,ransomware")).text
    assert "1.1.1.1" in body and "2.2.2.2" in body
    assert "3.3.3.3" not in body


async def test_tags_param_and_tag_query_are_merged(member_client, tagged):
    body = (await member_client.get("/intel/entities-partial?tags=ransomware&q=tag:apt28")).text
    assert "1.1.1.1" in body and "2.2.2.2" in body


async def test_tags_param_and_tag_query_union_includes_a_tag_only_match(member_client, tagged, ransomware_only):
    """The case that distinguishes a union from an intersection.

    `?tags=ransomware&q=tag:apt28` must not AND: merging both into `tag_list` *and*
    separately applying the `tag:` term in `apply_entity_filters` would drop an entity
    carrying only `ransomware`. Every entity in the base fixture that has `ransomware`
    also has `apt28`, so the assertion above cannot see the difference — this one can.
    """
    body = (await member_client.get("/intel/entities-partial?tags=ransomware&q=tag:apt28")).text
    assert ransomware_only.value in body, "tags= and q=tag: were intersected, not unioned"


@pytest.fixture()
async def ransomware_only(async_db, tagged):
    e = Entity(value="4.4.4.4", entity_type="ip_address", job_count=1)
    async_db.add(e)
    await async_db.commit()
    async_db.add(EntityTag(entity_id=e.id, tag="ransomware", color="orange"))
    await async_db.commit()
    await async_db.refresh(e)
    return e


async def test_unknown_tag_matches_nothing(member_client, tagged):
    body = (await member_client.get("/intel/entities-partial?tags=nosuchtag")).text
    for value in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        assert value not in body


async def test_dashboard_tag_chips_link_to_the_filtered_view(member_client, tagged):
    body = (await member_client.get("/intel/entities-partial")).text
    assert "/intel?tags=apt28" in body
    assert "toggleTag($el.dataset.tag)" in body, "chips must not interpolate tag text into JS"


async def test_entity_header_tag_chips_are_pivot_links(member_client, tagged):
    body = (await member_client.get(f"/intel/entities/{tagged['a'].id}")).text
    assert "/intel?tags=apt28" in body


async def test_case_entity_rows_render_tag_chips(member_client, async_db, member_user, tagged):
    case = InvestigationCase(name="Tagged Case", created_by_user_id=member_user.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()
    async_db.add(CaseEntityLink(case_id=case.id, entity_id=tagged["a"].id, added_by_user_id=member_user.id))
    await async_db.commit()

    # The rows are lazy-loaded and paged, so `tags_by_entity` has to be bulk-loaded
    # per page in `case_entities_partial` rather than once in `case_detail`.
    body = (await member_client.get(f"/intel/cases/{case.id}/entities-partial")).text
    assert "/intel?tags=apt28" in body

    # The single-row re-render must carry tags too, or chips vanish on note save.
    row = await member_client.post(
        f"/intel/cases/{case.id}/entities/{tagged['a'].id}/note",
        data={"note": "pivot me"},
    )
    assert row.status_code == 200
    assert "/intel?tags=apt28" in row.text


async def test_tags_json_returns_counts(member_client, tagged):
    rows = (await member_client.get("/intel/tags.json")).json()
    by_tag = {r["tag"]: r for r in rows}
    assert by_tag["apt28"]["count"] == 2
    assert by_tag["ransomware"]["count"] == 1
    assert by_tag["apt28"]["color"] == "red"


async def test_tags_json_filters_by_q(member_client, tagged):
    rows = (await member_client.get("/intel/tags.json?q=ransom")).json()
    assert [r["tag"] for r in rows] == ["ransomware"]


async def test_tags_json_requires_member(user_client, tagged):
    assert (await user_client.get("/intel/tags.json")).status_code == 403


# ── Tag colour is unique per tag name ────────────────────────────────────────


async def test_tag_colour_is_global_per_tag_name(member_client, async_db, entity):
    """The same label in different colours on different entities makes chips unscannable."""
    other = Entity(value="9.9.9.9", entity_type="ip_address", job_count=1)
    async_db.add(other)
    await async_db.commit()
    await async_db.refresh(other)

    await member_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "apt28", "color": "red"})
    await member_client.post(f"/intel/entities/{other.id}/tags", data={"tag": "apt28", "color": "blue"})

    rows = (await async_db.execute(select(EntityTag).where(EntityTag.tag == "apt28"))).scalars().all()
    assert len(rows) == 2
    assert {r.color for r in rows} == {"blue"}, "a tag name must carry one colour everywhere"


async def test_recolouring_a_tag_updates_every_entity(member_client, async_db, entity):
    other = Entity(value="8.8.4.4", entity_type="ip_address", job_count=1)
    async_db.add(other)
    await async_db.commit()
    await async_db.refresh(other)

    for target in (entity.id, other.id):
        await member_client.post(f"/intel/entities/{target}/tags", data={"tag": "shared", "color": "green"})
    # Recolour from one entity; both must follow.
    await member_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "shared", "color": "purple"})

    rows = (await async_db.execute(select(EntityTag).where(EntityTag.tag == "shared"))).scalars().all()
    assert {r.color for r in rows} == {"purple"}


async def test_add_tag_form_offers_existing_tags(member_client, async_db, entity):
    """Reuse must be the easy path, or the vocabulary fills with near-duplicates.

    Not a native <datalist>, which browser chrome renders as plain text: it cannot show a
    tag's colour, counts only fit as a label hack, and nothing distinguishes "pick the
    existing apt28" from "coin a new apt-28". A combobox — each option is the tag's own
    coloured chip with its usage count, and creating a new tag is a separate, explicit
    affordance.
    """
    await member_client.post(f"/intel/entities/{entity.id}/tags", data={"tag": "apt28", "color": "red"})
    body = (await member_client.get(f"/intel/entities/{entity.id}")).text
    # `tagCombobox(` rather than `tagCombobox()`: the labelling call sites pass a `max`
    # so several tags can go on in one submission, while rename and merge stay single.
    assert "tagCombobox(" in body, "the tag input must be backed by the searchable combobox"
    assert 'x-for="(t, i) in matches()"' in body, "existing tags must be listed as you type"
    assert 'x-if="canCreate()"' in body, "creating a new tag must be an explicit option"

    app_js = (await member_client.get("/static/app.js")).text
    assert "window.tagCombobox = tagCombobox;" in app_js
    assert "/intel/tags.json" in app_js, "options come from the existing-tags endpoint"


# ── Case timeline entity filter is a search box ──────────────────────────────


async def test_case_timeline_entity_filter_is_a_search_box(member_client, async_db, member_user, entity, job, fake_redis):
    """A case can carry thousands of entities; a <select> of them is unusable."""
    case = InvestigationCase(name="TL Case", created_by_user_id=member_user.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()
    async_db.add_all(
        [
            CaseEntityLink(case_id=case.id, entity_id=entity.id, added_by_user_id=member_user.id),
            CaseJobLink(case_id=case.id, job_id=job.id, added_by_user_id=member_user.id),
        ]
    )
    await async_db.commit()

    body = (await member_client.get(f"/intel/cases/{case.id}/timeline-partial")).text
    assert "caseEntityFilter(" in body
    assert 'name="entity_id"' in body
    assert '<select name="entity_id"' not in body, "entity filter must not be a full <select> any more"


async def test_case_entities_json_searches_case_members_only(member_client, async_db, member_user, entity):
    outside = Entity(value="not-in-case.example", entity_type="domain", job_count=5)
    async_db.add(outside)
    case = InvestigationCase(name="Scoped Case", created_by_user_id=member_user.id, is_shared=True)
    async_db.add(case)
    await async_db.commit()
    async_db.add(CaseEntityLink(case_id=case.id, entity_id=entity.id, added_by_user_id=member_user.id))
    await async_db.commit()

    rows = (await member_client.get(f"/intel/cases/{case.id}/entities.json")).json()
    values = {r["value"] for r in rows}
    assert entity.value in values
    assert outside.value not in values, "search must not leak entities outside the case"

    assert (await member_client.get(f"/intel/cases/{case.id}/entities.json?q=x")).json() == []


async def test_case_entities_json_requires_case_visibility(test_client, async_db, entity):
    owner = await _create_user(async_db, email="tlowner@qol.example.com")
    await _create_user(async_db, email="tlother@qol.example.com")
    case = InvestigationCase(name="Hidden", created_by_user_id=owner.id, is_shared=False)
    async_db.add(case)
    await async_db.commit()

    await _login(test_client, "tlother@qol.example.com")
    assert (await test_client.get(f"/intel/cases/{case.id}/entities.json")).status_code == 404


# ── /intel/ioc-feed: MISP branch shares the JSON branch's result set ─────────


class TestIocFeedMispConsistency:
    """The MISP branch must not re-run its own near-copy of the entity query and `zip()`
    the two result sets positionally. Copies diverge: `_build_ioc_data` skips the type
    filter when no requested type is valid, while a copy applying `.in_([])` would make
    `?format=misp&types=bogus` return an event with zero entities while
    `?format=json&types=bogus` returns every entity.
    """

    @staticmethod
    async def _seed(async_db):
        from app.models import Entity

        async_db.add_all(
            [
                Entity(value="10.1.1.1", entity_type="ip_address", job_count=1),
                Entity(value="evil.example", entity_type="domain", job_count=1),
            ]
        )
        await async_db.commit()

    async def test_unknown_type_filter_agrees_across_formats(self, member_client, async_db):
        await self._seed(async_db)

        json_resp = await member_client.get("/intel/ioc-feed", params={"types": "bogus"})
        misp_resp = await member_client.get("/intel/ioc-feed", params={"format": "misp", "types": "bogus"})

        # An unknown type is refused rather than dropped (tests/test_ioc_feed_filters.py) —
        # by every format alike.
        assert json_resp.status_code == misp_resp.status_code == 400, "MISP and JSON branches disagree on the same filter"

    async def test_valid_type_filter_agrees_across_formats(self, member_client, async_db):
        await self._seed(async_db)

        json_rows = (await member_client.get("/intel/ioc-feed", params={"types": "domain"})).json()
        misp = (await member_client.get("/intel/ioc-feed", params={"format": "misp", "types": "domain"})).json()

        assert len(json_rows) == 1
        assert len(misp["Event"]["Attribute"]) == 1


async def test_tag_combobox_renders_its_colour_swatches(member_client, async_db, entity):
    """Colour picking silently did nothing, twice, for two different reasons.

    First the picker was a native <select> inside the dropdown: clicking it blurred the
    input, and the deferred close unmounted the control before it could be used. Then, once
    it became swatches, the Jinja loop rendered *nothing* — a macro cannot see the caller's
    context without `with context`, so `tag_colors` was undefined and the loop was empty.

    Neither failure produced an error anywhere. This asserts the swatches actually exist.
    """
    from app.routers.intel_tags import TAG_COLORS

    body = (await member_client.get(f"/intel/entities/{entity.id}")).text
    for colour in TAG_COLORS:
        assert f"setColor('{colour}')" in body, f"no swatch for {colour} — is the macro imported `with context`?"
    # Focus must not close the panel, or the swatches are unreachable again.
    assert "@blur=" not in body.split('name="tag"')[1][:400], "the combobox must not close on the input's blur"
    assert "$event.currentTarget.contains($event.relatedTarget)" in body


async def test_tag_combobox_swatches_reach_the_dashboard_and_rule_form(member_client, async_db, entity):
    """All three call sites import the macro, so all three can break the same way."""
    from app.routers.intel_tags import TAG_COLORS

    for url in ("/intel", "/intel/rules"):
        body = (await member_client.get(url)).text
        assert f"setColor('{TAG_COLORS[0]}')" in body, f"{url} lost its colour swatches"


class TestTheTagFieldShowsAPill:
    """Select2 shape: once a tag is chosen it is a coloured pill inside the field, not text.

    A tag *is* a coloured chip everywhere else in the app, and a field that renders it as
    plain characters makes "I picked the existing apt28" and "I am about to coin apt-28"
    look identical at the moment it matters.
    """

    async def test_every_picker_renders_the_pill_and_its_hidden_carriers(self, member_client, admin_client):
        # Not /jobs: with no jobs seeded the whole list pane — bulk bar included — is
        # behind `{% if jobs %}`, so its absence would say nothing about the control.
        for client, url in ((member_client, "/intel/tags"), (member_client, "/intel")):
            body = (await client.get(url)).text
            assert "lt-combo-pill" in body, f"{url} has no pill"
            assert "lt-combo-input" in body, f"{url} has no input inside the field"
            assert 'x-ref="value"' in body, f"{url} does not carry the submitted value"

    async def test_the_value_is_written_not_bound(self, member_client):
        """htmx serialises synchronously inside the submit event while Alpine applies
        bindings on its own scheduler — a `:value` here can hand the server the previous
        selection, which is the documented trap that bit the case-timeline filter."""
        body = (await member_client.get("/intel/tags")).text
        assert 'x-ref="value"' in body
        assert ':value="selected' not in body, "the submitted value must not be a binding"

    def test_the_colour_map_is_defined_once(self):
        """Twelve literal Tailwind classes, spelled out where the scanner can see them —
        `bg-{color}-900/60` assembled at runtime has no rule behind it in a built stylesheet."""
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent / "app" / "templates" / "intel" / "partials"
        chip = (root / "_tag_chip.html").read_text()
        combo = (root / "_tag_combobox.html").read_text()

        assert "macro alpine_tag_classes" in chip
        assert "bg-rose-900/60" in chip
        assert "bg-rose-900/60" not in combo, "the combobox re-copied the palette"

    def test_the_pill_css_is_ordered_against_the_primitives_it_overrides(self):
        """`.lt-combo` must beat `.lt-field`'s fixed `height`, and `.lt-combo-pill` must beat
        `.lt-chip`'s. Same specificity, so source order is the whole mechanism."""
        from pathlib import Path

        css = (Path(__file__).resolve().parent.parent / "app" / "templates" / "base.html").read_text()
        assert css.index(".lt-field {") < css.index(".lt-combo {")
        assert css.index(".lt-chip {") < css.index(".lt-combo-pill {")

    def test_the_add_form_can_actually_focus_its_input(self):
        """`$refs` resolves from a component's root *outwards*, and `x-ref="tagInput"` is
        registered on the nested combobox — a descendant. `entityTagInput.open()` reaching
        for it was a silent no-op, so the add form opened with no caret in it."""
        from pathlib import Path

        js = (Path(__file__).resolve().parent.parent / "app" / "static" / "app.js").read_text()
        import re

        block = js[js.index("function entityTagInput()") : js.index("window.entityTagInput")]
        # Strip comments first: a comment may name the pattern it warns against, and a raw
        # substring search would find it there.
        code = re.sub(r"//.*", "", block)
        assert "$refs.tagInput" not in code, "still reaching into a descendant's refs"
        assert "querySelector('.lt-combo-input')" in block
