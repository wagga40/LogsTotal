"""The tag manager: rename, merge, recolour and delete a tag everywhere.

Tags were creatable only from a four-control row on the entity page, with no way to see
what tags existed, fix a typo in one, fold two together, or retire one. The vocabulary an
analyst accumulates is most of the value of tagging, so it needs somewhere to be curated.

The subtle part is the unique constraint. `uq_entity_tag(entity_id, tag)` means renaming
`a` to `b` collides on any entity that already carries *both*, so a plain
`UPDATE ... SET tag='b' WHERE tag='a'` raises. `_merge_tag_into` deletes the colliding rows
first — `test_rename_onto_an_existing_tag_merges_without_collision` is the case that fails
if anyone simplifies it back.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.models import Entity, EntityTag, IntelRule, SiteSettings


@pytest.fixture()
async def tag_data(async_db):
    """Three entities. `a` carries both alpha and beta — the collision case."""
    a = Entity(value="1.1.1.1", entity_type="ip_address", job_count=1)
    b = Entity(value="2.2.2.2", entity_type="ip_address", job_count=1)
    c = Entity(value="3.3.3.3", entity_type="ip_address", job_count=1)
    async_db.add_all([a, b, c])
    await async_db.commit()
    async_db.add_all(
        [
            EntityTag(entity_id=a.id, tag="alpha", color="red"),
            EntityTag(entity_id=a.id, tag="beta", color="blue"),
            EntityTag(entity_id=b.id, tag="alpha", color="red"),
            EntityTag(entity_id=c.id, tag="gamma", color="green"),
        ]
    )
    await async_db.commit()
    for o in (a, b, c):
        await async_db.refresh(o)
    return {"a": a, "b": b, "c": c}


async def _tags_of(async_db, entity_id: int) -> set[str]:
    rows = (await async_db.execute(select(EntityTag.tag).where(EntityTag.entity_id == entity_id))).scalars().all()
    return set(rows)


async def _count(async_db, tag: str) -> int:
    return await async_db.scalar(select(func.count(EntityTag.id)).where(EntityTag.tag == tag)) or 0


class TestPage:
    async def test_page_lists_tags_with_counts(self, member_client, tag_data):
        body = (await member_client.get("/intel/tags")).text
        assert "alpha" in body and "beta" in body and "gamma" in body

    async def test_search_narrows(self, member_client, tag_data):
        body = (await member_client.get("/intel/tags?q=alph")).text
        assert "alpha" in body
        assert ">gamma<" not in body

    async def test_basic_user_is_refused(self, user_client, tag_data):
        assert (await user_client.get("/intel/tags")).status_code == 403

    async def test_anonymous_is_refused(self, test_client, tag_data):
        assert (await test_client.get("/intel/tags")).status_code in (401, 403)


class TestRename:
    async def test_renames_everywhere(self, member_client, async_db, tag_data):
        resp = await member_client.post("/intel/tags/rename", data={"tag": "gamma", "new_tag": "delta"})
        assert resp.status_code == 200
        assert await _count(async_db, "gamma") == 0
        assert await _count(async_db, "delta") == 1

    async def test_rename_onto_an_existing_tag_merges_without_collision(self, member_client, async_db, tag_data):
        """`a` carries alpha AND beta — a plain UPDATE would violate uq_entity_tag."""
        resp = await member_client.post("/intel/tags/rename", data={"tag": "alpha", "new_tag": "beta"})
        assert resp.status_code == 200
        assert await _count(async_db, "alpha") == 0
        # a already had beta (not duplicated); b's alpha became beta.
        assert await _count(async_db, "beta") == 2
        assert await _tags_of(async_db, tag_data["a"].id) == {"beta"}
        assert await _tags_of(async_db, tag_data["b"].id) == {"beta"}

    async def test_rename_normalizes(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/rename", data={"tag": "gamma", "new_tag": "  DeLTa  "})
        assert await _count(async_db, "delta") == 1

    async def test_rename_onto_a_built_in_label_name_now_merges_into_it(self, member_client, async_db, tag_data):
        """`lolbin` is an ordinary tag, one a built-in rule applies, so renaming onto it is
        an ordinary rename onto an existing name — which this manager treats as a merge.

        The *name* is not what makes a tag protected — a live rule is, and this fixture seeds
        none, which is why this passes beside
        `TestRuleMaintainedTagsResistAMerge::test_renaming_onto_one_is_the_same_refusal`.
        Seed built-in rules into `conftest` and this one flips; that would be the seeding
        talking, not a regression here.
        """
        resp = await member_client.post("/intel/tags/rename", data={"tag": "gamma", "new_tag": "lolbin"})
        assert resp.status_code == 200
        assert await _count(async_db, "gamma") == 0
        assert await _count(async_db, "lolbin") == 1

    async def test_empty_rename_is_refused(self, member_client, async_db, tag_data):
        assert (await member_client.post("/intel/tags/rename", data={"tag": "gamma", "new_tag": "   "})).status_code == 400
        assert await _count(async_db, "gamma") == 1


class TestMerge:
    async def test_merges_and_is_idempotent(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/merge", data={"tag": "alpha", "into": "beta"})
        assert await _count(async_db, "alpha") == 0
        assert await _count(async_db, "beta") == 2
        # Running it again must not raise or change anything.
        resp = await member_client.post("/intel/tags/merge", data={"tag": "alpha", "into": "beta"})
        assert resp.status_code == 200
        assert await _count(async_db, "beta") == 2

    async def test_merging_into_itself_is_a_no_op(self, member_client, async_db, tag_data):
        resp = await member_client.post("/intel/tags/merge", data={"tag": "alpha", "into": "alpha"})
        assert resp.status_code == 200
        assert await _count(async_db, "alpha") == 2


class TestRecolorAndDelete:
    async def test_recolor_applies_to_every_row(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/recolor", data={"tag": "alpha", "color": "purple"})
        colors = (await async_db.execute(select(EntityTag.color).where(EntityTag.tag == "alpha"))).scalars().all()
        assert set(colors) == {"purple"}

    async def test_unknown_colour_falls_back_to_gray(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/recolor", data={"tag": "alpha", "color": "chartreuse"})
        colors = (await async_db.execute(select(EntityTag.color).where(EntityTag.tag == "alpha"))).scalars().all()
        assert set(colors) == {"gray"}

    async def test_delete_removes_from_every_entity(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/delete", data={"tag": "alpha"})
        assert await _count(async_db, "alpha") == 0
        # Other tags are untouched.
        assert await _count(async_db, "beta") == 1
        assert await _count(async_db, "gamma") == 1

    async def test_delete_is_refused_for_a_basic_user(self, user_client, async_db, tag_data):
        assert (await user_client.post("/intel/tags/delete", data={"tag": "alpha"})).status_code == 403
        assert await _count(async_db, "alpha") == 2


class TestBulkTagging:
    """Tagging was one entity at a time from its own page, which made the obvious
    workflow — search, then label what you found — impractical."""

    async def test_bulk_tag_applies_to_every_selected_entity(self, member_client, async_db, tag_data):
        ids = f"{tag_data['a'].id},{tag_data['b'].id},{tag_data['c'].id}"
        resp = await member_client.post("/intel/entities/bulk-tag", data={"entity_ids": ids, "tag": "sweep", "color": "teal"})
        assert resp.status_code == 200
        assert await _count(async_db, "sweep") == 3

    async def test_bulk_tag_is_idempotent(self, member_client, async_db, tag_data):
        ids = f"{tag_data['a'].id},{tag_data['b'].id}"
        await member_client.post("/intel/entities/bulk-tag", data={"entity_ids": ids, "tag": "alpha"})
        # `a` and `b` already carry alpha; re-applying must not duplicate or raise.
        assert await _count(async_db, "alpha") == 2

    async def test_bulk_tag_ignores_unknown_ids(self, member_client, async_db, tag_data):
        """A stale selection must not create rows pointing at deleted entities."""
        resp = await member_client.post("/intel/entities/bulk-tag", data={"entity_ids": f"{tag_data['a'].id},999999", "tag": "sweep"})
        assert resp.status_code == 200
        assert await _count(async_db, "sweep") == 1

    async def test_bulk_tag_normalizes_and_keeps_one_colour_per_name(self, member_client, async_db, tag_data):
        await member_client.post("/intel/entities/bulk-tag", data={"entity_ids": str(tag_data["c"].id), "tag": "  ALPHA ", "color": "purple"})
        colors = (await async_db.execute(select(EntityTag.color).where(EntityTag.tag == "alpha"))).scalars().all()
        assert set(colors) == {"purple"}, "bulk tagging broke the one-colour-per-name invariant"

    async def test_bulk_untag_removes_only_from_the_selection(self, member_client, async_db, tag_data):
        resp = await member_client.post("/intel/entities/bulk-untag", data={"entity_ids": str(tag_data["a"].id), "tag": "alpha"})
        assert resp.status_code == 200
        assert await _tags_of(async_db, tag_data["a"].id) == {"beta"}
        assert await _tags_of(async_db, tag_data["b"].id) == {"alpha"}

    async def test_bulk_tag_requires_a_selection(self, member_client, tag_data):
        assert (await member_client.post("/intel/entities/bulk-tag", data={"entity_ids": "", "tag": "x"})).status_code == 400

    async def test_bulk_tag_refused_for_basic_user(self, user_client, async_db, tag_data):
        assert (await user_client.post("/intel/entities/bulk-tag", data={"entity_ids": str(tag_data["a"].id), "tag": "x"})).status_code == 403
        assert await _count(async_db, "x") == 0


class TestMergeColour:
    """A merge must leave one colour behind.

    Moved rows keep the colour they had under the old name, so without an explicit colour
    pass `beta` ends up red on some entities and blue on others — which is exactly the
    one-colour-per-name invariant that makes chips scannable.
    """

    async def _colours(self, async_db, tag):
        return set((await async_db.execute(select(EntityTag.color).where(EntityTag.tag == tag))).scalars().all())

    async def test_merge_leaves_a_single_colour(self, member_client, async_db, tag_data):
        # alpha is red on two entities, beta is blue on one.
        await member_client.post("/intel/tags/merge", data={"tag": "alpha", "into": "beta"})
        assert await self._colours(async_db, "beta") == {"blue"}, "merged rows kept the source colour"

    async def test_merge_can_choose_the_surviving_colour(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/merge", data={"tag": "alpha", "into": "beta", "color": "purple"})
        assert await self._colours(async_db, "beta") == {"purple"}

    async def test_merge_ignores_an_unknown_colour(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/merge", data={"tag": "alpha", "into": "beta", "color": "chartreuse"})
        assert await self._colours(async_db, "beta") == {"blue"}

    async def test_rename_to_a_fresh_name_keeps_the_source_colour(self, member_client, async_db, tag_data):
        """Nothing to inherit from, so snapping to grey would lose information."""
        await member_client.post("/intel/tags/rename", data={"tag": "gamma", "new_tag": "delta"})
        assert await self._colours(async_db, "delta") == {"green"}

    async def test_rename_onto_an_existing_name_takes_the_targets_colour(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/rename", data={"tag": "alpha", "new_tag": "beta"})
        assert await self._colours(async_db, "beta") == {"blue"}

    async def test_rename_can_choose_a_colour(self, member_client, async_db, tag_data):
        await member_client.post("/intel/tags/rename", data={"tag": "gamma", "new_tag": "delta", "color": "teal"})
        assert await self._colours(async_db, "delta") == {"teal"}


class TestRuleMaintainedTagsResistAMerge:
    """A name a live shared rule re-applies cannot be folded, in either direction.

    Both directions end badly and neither is recoverable. Folding `lolbin` *away* is
    undone by the next matching job — history ends up under the new name while the rule
    keeps minting the old one, so the vocabulary silently splits in two. Folding something
    *into* it puts a name that means "the shared rule matched this" onto entities the rule
    never matched.

    Live is the operative word: the guard reads real `IntelRule` rows rather than a list of
    reserved names, so a rule an admin switched off — or a whole instance running with
    `builtin_rules_enabled` false — leaves an ordinary tag that merges like any other. A
    blanket refusal would block a legitimate merge there, and would say "it comes back on
    the next matching job" about a name that will not.
    """

    @pytest.fixture()
    async def shared_rule(self, async_db, tag_data):
        """A shared rule that re-applies `lolbin`, and one entity already carrying it."""
        async_db.add(
            IntelRule(
                name="LOLBAS executables",
                is_builtin=True,
                builtin_key="lolbin",
                query="list:lolbas",
                action_tag="lolbin",
                action_tag_color="orange",
            )
        )
        async_db.add(EntityTag(entity_id=tag_data["c"].id, tag="lolbin", color="orange"))
        await async_db.commit()

    async def _switch_off_the_site(self, async_db):
        site = await async_db.get(SiteSettings, 1)
        if site is None:
            site = SiteSettings(id=1)
            async_db.add(site)
        site.builtin_rules_enabled = False
        await async_db.commit()

    async def test_folding_one_away_is_refused(self, member_client, async_db, shared_rule):
        resp = await member_client.post("/intel/tags/merge", data={"tag": "lolbin", "into": "alpha"})
        assert resp.status_code == 200, "a refusal htmx will not swap is a refusal nobody sees"
        assert await _count(async_db, "lolbin") == 1
        assert await _count(async_db, "alpha") == 2

    async def test_folding_something_into_one_is_refused(self, member_client, async_db, shared_rule):
        resp = await member_client.post("/intel/tags/merge", data={"tag": "alpha", "into": "lolbin"})
        assert resp.status_code == 200
        assert await _count(async_db, "alpha") == 2
        assert await _count(async_db, "lolbin") == 1

    async def test_renaming_onto_one_is_the_same_refusal(self, member_client, async_db, shared_rule):
        """The back door: renaming onto an existing name *is* a merge, via `merge_tag_into`."""
        resp = await member_client.post("/intel/tags/rename", data={"tag": "gamma", "new_tag": "lolbin"})
        assert resp.status_code == 200
        assert await _count(async_db, "gamma") == 1
        assert await _count(async_db, "lolbin") == 1

    async def test_renaming_onto_one_the_rule_has_not_written_yet_is_refused_too(self, member_client, async_db, tag_data):
        """The rule need not have fired. Nothing carries `dga` yet, so this is a rename to a
        fresh name by the existence test — but the first matching job pollutes it exactly
        as a merge would, and "you may rename into it until the rule fires" is not a rule
        anyone could hold in their head."""
        async_db.add(IntelRule(name="DGA-looking domains", is_builtin=True, builtin_key="dga", query="re:/x/", action_tag="dga"))
        await async_db.commit()
        resp = await member_client.post("/intel/tags/rename", data={"tag": "gamma", "new_tag": "dga"})
        assert resp.status_code == 200
        assert await _count(async_db, "gamma") == 1
        assert await _count(async_db, "dga") == 0

    async def test_renaming_one_to_a_fresh_name_is_still_allowed(self, member_client, async_db, shared_rule):
        """Deliberately not refused. It is equally futile — the rule re-coins `lolbin` — and
        the row's amber mark says so, but a rename is reversible: you can rename back. A
        merge cannot be unpicked, which is the whole reason merging is the one refused."""
        resp = await member_client.post("/intel/tags/rename", data={"tag": "lolbin", "new_tag": "lolbinary"})
        assert resp.status_code == 200
        assert await _count(async_db, "lolbin") == 0
        assert await _count(async_db, "lolbinary") == 1

    async def test_a_switched_off_rule_leaves_an_ordinary_tag(self, member_client, async_db, shared_rule):
        rule = (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "lolbin"))).scalar_one()
        rule.enabled = False
        await async_db.commit()
        await member_client.post("/intel/tags/merge", data={"tag": "lolbin", "into": "alpha"})
        assert await _count(async_db, "lolbin") == 0
        assert await _count(async_db, "alpha") == 3

    async def test_the_site_switch_leaves_ordinary_tags(self, member_client, async_db, shared_rule):
        await self._switch_off_the_site(async_db)
        await member_client.post("/intel/tags/merge", data={"tag": "lolbin", "into": "alpha"})
        assert await _count(async_db, "lolbin") == 0
        assert await _count(async_db, "alpha") == 3

    async def test_the_refusal_names_the_rule_and_points_at_it(self, member_client, shared_rule):
        """A refusal an analyst cannot act on is a dead end — and a member cannot switch a
        shared rule off (`_rule_can_edit` is admin-only for those), so the notice has to say
        where the switch is rather than imply they can throw it."""
        body = (await member_client.post("/intel/tags/merge", data={"tag": "lolbin", "into": "alpha"})).text
        assert "is maintained by the shared rule" in body
        assert "LOLBAS executables" in body
        assert 'href="/intel/rules"' in body

    async def test_the_amber_mark_follows_the_same_liveness(self, member_client, async_db, shared_rule):
        """The mark must not appear for a switched-off rule, promising a reappearance that is
        never coming. One predicate behind the mark and the refusal, or the page and the
        guard disagree about the same tag."""
        assert 'title="Added by a shared rule' in (await member_client.get("/intel/tags")).text
        rule = (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "lolbin"))).scalar_one()
        rule.enabled = False
        await async_db.commit()
        assert 'title="Added by a shared rule' not in (await member_client.get("/intel/tags")).text

    async def test_the_refusal_scrolls_itself_into_view(self, member_client, shared_rule):
        """The notice renders at the top of the region; the row whose form was submitted can
        be a screenful below it. Only a refusal moves the page — a recolour must not."""
        refused = await member_client.post("/intel/tags/merge", data={"tag": "lolbin", "into": "alpha"})
        assert refused.headers.get("HX-Reswap") == "outerHTML show:top"
        ok = await member_client.post("/intel/tags/recolor", data={"tag": "alpha", "color": "purple"})
        assert "HX-Reswap" not in ok.headers

    async def test_the_merge_control_is_disabled_on_a_marked_row(self, member_client, shared_rule):
        """Up front, not after typing a target. No route test can see this — the server
        renders a working page either way."""
        import re as _re

        body = (await member_client.get("/intel/tags")).text
        # A *literal* `disabled`, never Alpine's `:disabled` — `\bdisabled\b` matches inside
        # `:disabled` because `:` is a non-word character, and the merge form's own submit
        # carries `:disabled="isEmpty()"`. The two say different things and the lookbehind is
        # what keeps them apart.
        buttons = _re.findall(r"<button[^>]*>\s*Merge\s*</button>", body)
        refused = [b for b in buttons if _re.search(r"(?<![:\w-])disabled(?=[\s>=])", b)]
        assert len(refused) == 1, f"exactly the one rule-maintained row should refuse up front, got {len(refused)} of {len(buttons)}"
        live = _re.findall(r'@click="merging = true"', body)
        assert len(live) == 3, "alpha, beta and gamma are ordinary tags and stay mergeable"


class TestMergeRefusalMessage:
    """The refusal itself is pure: which side is rule-maintained, and whether a rename is
    really a merge. Tier 1, because every branch of it is a sentence someone has to act on.
    """

    def test_an_ordinary_fold_is_not_refused(self):
        from app.routers.intel_tags import _merge_refusal

        assert _merge_refusal("alpha", "beta", {}, is_merge=True) == ""

    def test_the_target_is_refused_whether_or_not_it_is_a_merge(self):
        from app.routers.intel_tags import _merge_refusal

        maintained = {"lolbin": ["LOLBAS executables"]}
        assert "never matched" in _merge_refusal("alpha", "lolbin", maintained, is_merge=True)
        assert "never matched" in _merge_refusal("alpha", "lolbin", maintained, is_merge=False)

    def test_the_source_is_refused_only_when_the_rename_is_a_merge(self):
        from app.routers.intel_tags import _merge_refusal

        maintained = {"lolbin": ["LOLBAS executables"]}
        assert "comes back" in _merge_refusal("lolbin", "alpha", maintained, is_merge=True)
        assert _merge_refusal("lolbin", "lolbinary", maintained, is_merge=False) == ""

    def test_several_rules_are_not_named_individually(self):
        """One name is a fact the reader can act on; three is a list they have to hunt
        through, and the link goes to the page holding all of them anyway."""
        from app.routers.intel_tags import _merge_refusal

        msg = _merge_refusal("lolbin", "alpha", {"lolbin": ["One", "Two"]}, is_merge=True)
        assert "shared rules" in msg and "One" not in msg


class TestTagVocabulary:
    """A tag can exist before anything carries it.

    `EntityTag` is the association and cannot represent an unused tag, so without a
    definition the only way to bring one into existence would be applying it to something —
    which makes "agree a vocabulary, then label against it" impossible, and leaves the
    manager able to edit only tags work has already been done in.
    """

    async def test_create_adds_an_unused_tag(self, member_client, async_db, tag_data):
        from app.models import TagDefinition

        resp = await member_client.post("/intel/tags", data={"tag": "planned", "color": "teal"})
        assert resp.status_code == 200
        row = (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "planned"))).scalar_one()
        assert row.color == "teal"
        assert await _count(async_db, "planned") == 0, "creating a tag must not tag anything"

    async def test_an_unused_tag_is_listed_and_offered(self, member_client, tag_data):
        await member_client.post("/intel/tags", data={"tag": "planned", "color": "teal"})
        assert "planned" in (await member_client.get("/intel/tags")).text
        assert "planned" in {r["tag"] for r in (await member_client.get("/intel/tags.json")).json()}

    async def test_create_normalizes_and_is_idempotent(self, member_client, async_db, tag_data):
        from app.models import TagDefinition

        await member_client.post("/intel/tags", data={"tag": "  PlanNED "})
        await member_client.post("/intel/tags", data={"tag": "planned"})
        rows = (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "planned"))).scalars().all()
        assert len(rows) == 1

    async def test_create_accepts_a_built_in_label_name(self, member_client, tag_data):
        """No name is reserved — see `parse_tag_write`'s docstring."""
        assert (await member_client.post("/intel/tags", data={"tag": "lolbin"})).status_code == 200

    async def test_create_refuses_an_empty_name(self, member_client, tag_data):
        assert (await member_client.post("/intel/tags", data={"tag": "   "})).status_code == 400

    async def test_basic_user_cannot_create(self, user_client, tag_data):
        assert (await user_client.post("/intel/tags", data={"tag": "nope"})).status_code == 403

    async def test_applying_a_tag_registers_it_in_the_vocabulary(self, member_client, async_db, tag_data):
        """Otherwise a tag vanishes from the picker the moment its last entity loses it."""
        from app.models import TagDefinition

        await member_client.post("/intel/entities/bulk-tag", data={"entity_ids": str(tag_data["a"].id), "tag": "coined", "color": "rose"})
        row = (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "coined"))).scalar_one()
        assert row.color == "rose"

    async def test_recolour_reaches_an_unused_tag(self, member_client, async_db, tag_data):
        from app.models import TagDefinition

        await member_client.post("/intel/tags", data={"tag": "planned", "color": "teal"})
        await member_client.post("/intel/tags/recolor", data={"tag": "planned", "color": "indigo"})
        row = (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "planned"))).scalar_one()
        assert row.color == "indigo"

    async def test_delete_removes_the_definition_too(self, member_client, async_db, tag_data):
        from app.models import TagDefinition

        await member_client.post("/intel/tags", data={"tag": "planned"})
        await member_client.post("/intel/tags/delete", data={"tag": "planned"})
        assert (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "planned"))).scalar_one_or_none() is None

    async def test_rename_carries_the_definition(self, member_client, async_db, tag_data):
        from app.models import TagDefinition

        await member_client.post("/intel/tags", data={"tag": "planned"})
        await member_client.post("/intel/tags/rename", data={"tag": "planned", "new_tag": "scheduled"})
        assert (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "planned"))).scalar_one_or_none() is None
        assert (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "scheduled"))).scalar_one_or_none() is not None

    async def test_merge_drops_the_source_definition(self, member_client, async_db, tag_data):
        from app.models import TagDefinition

        await member_client.post("/intel/tags", data={"tag": "src"})
        await member_client.post("/intel/tags", data={"tag": "dst"})
        await member_client.post("/intel/tags/merge", data={"tag": "src", "into": "dst"})
        defs = (await async_db.execute(select(TagDefinition.tag).where(TagDefinition.tag.in_(["src", "dst"])))).scalars().all()
        assert defs == ["dst"]


class TestTheVocabularyCoversBothLinkTables:
    """One tag, one colour, whichever kind of thing carries it.

    Jobs became taggable after entities did, so every vocabulary write had to grow a second
    leg. The interesting case is a tag used *only* on jobs: the colour-fallback chain used
    to read `min(EntityTag.color)` for the target and then for the source, both of which are
    NULL there — so the recolour pass was skipped and the moved rows kept their old-name
    colour, breaking the one-colour-per-name invariant for exactly the case that made the
    change necessary.
    """

    @staticmethod
    async def _tagged_job(async_db, tag: str, color: str) -> int:
        from app.models import AnalysisJob, JobStatus, JobTag, LogFile, TagDefinition, WorkflowDef

        if not (await async_db.execute(select(LogFile).where(LogFile.id == 900))).scalar_one_or_none():
            async_db.add(LogFile(id=900, original_filename="j.evtx", stored_filename="j.evtx", sha256="c" * 64, size_bytes=1))
            async_db.add(WorkflowDef(id=900, name="wf-tagged"))
            await async_db.commit()
        job = AnalysisJob(file_id=900, workflow_id=900, status=JobStatus.COMPLETED)
        async_db.add(job)
        await async_db.commit()
        await async_db.refresh(job)
        async_db.add(JobTag(job_id=job.id, tag=tag, color=color))
        async_db.add(TagDefinition(tag=tag, color=color))
        await async_db.commit()
        return job.id

    async def test_recolour_reaches_job_tags(self, member_client, async_db, tag_data):
        from app.models import JobTag

        job_id = await self._tagged_job(async_db, "jobs-only", "teal")
        await member_client.post("/intel/tags/recolor", data={"tag": "jobs-only", "color": "indigo"})

        row = (await async_db.execute(select(JobTag).where(JobTag.job_id == job_id))).scalar_one()
        assert row.color == "indigo"

    async def test_rename_reaches_job_tags(self, async_db, member_client, tag_data):
        from app.models import JobTag

        job_id = await self._tagged_job(async_db, "jobs-only", "teal")
        await member_client.post("/intel/tags/rename", data={"tag": "jobs-only", "new_tag": "jobs-renamed"})

        rows = (await async_db.execute(select(JobTag).where(JobTag.job_id == job_id))).scalars().all()
        assert [r.tag for r in rows] == ["jobs-renamed"]
        assert rows[0].color == "teal", "the source colour must carry over, not snap to grey"

    async def test_merging_two_jobs_only_tags_leaves_exactly_one_colour(self, async_db, member_client, tag_data):
        """The named case, and it needs two *different* colours to be visible.

        A colour-fallback chain reading EntityTag only finds NULL for both lookups on a tag
        that lives solely on jobs, so `set_tag_color` would be skipped entirely and every
        moved row would keep the colour it had under the old name — leaving one tag rendered
        two ways, which is the exact invariant the merge exists to preserve.
        """
        from app.models import JobTag

        src_job = await self._tagged_job(async_db, "src-jobs", "red")
        dst_job = await self._tagged_job(async_db, "dst-jobs", "blue")

        await member_client.post("/intel/tags/merge", data={"tag": "src-jobs", "into": "dst-jobs"})

        rows = (await async_db.execute(select(JobTag).where(JobTag.job_id.in_([src_job, dst_job])))).scalars().all()
        assert {r.tag for r in rows} == {"dst-jobs"}
        assert {r.color for r in rows} == {"blue"}, "one tag, one colour — the moved row must be recoloured too"

    async def test_delete_everywhere_reaches_job_tags(self, member_client, async_db, tag_data):
        from app.models import JobTag

        job_id = await self._tagged_job(async_db, "jobs-only", "teal")
        await member_client.post("/intel/tags/delete", data={"tag": "jobs-only"})

        assert (await async_db.execute(select(JobTag).where(JobTag.job_id == job_id))).scalars().all() == []

    async def test_the_manager_counts_jobs_separately_from_entities(self, member_client, async_db, tag_data):
        """`count` keeps meaning entities — the column has said Entities since it shipped,
        and quietly redefining it to a total would change every number without changing
        the heading."""
        from app.tags import tag_rows

        await self._tagged_job(async_db, "alpha", "red")
        rows = {r["tag"]: r for r in await tag_rows(async_db)}

        assert rows["alpha"]["job_count"] == 1
        assert rows["alpha"]["count"] >= 1, "the entity count is unchanged by a job tag"


class TestTheManagerControlsActuallyWork:
    """Two bugs that made the page look inert rather than wrong.

    Both are the kind a route test cannot see: the server always honoured what it was sent,
    and what it was sent was quietly not what the analyst chose.
    """

    def test_recently_used_puts_the_newest_first(self):
        """Ascending on `last_used` is "least recently used" — the list does change, just the
        wrong way, which reads as the control being ignored."""
        from datetime import datetime

        rows = [
            {"tag": "old", "last_used": datetime(2026, 1, 1), "count": 1, "job_count": 0},
            {"tag": "new", "last_used": datetime(2026, 8, 1), "count": 1, "job_count": 0},
            {"tag": "never", "last_used": None, "count": 0, "job_count": 0},
        ]
        # The sort is the tail of `tag_rows`; exercise it directly on the same key.
        rows.sort(key=lambda r: (r["last_used"] is None, -(r["last_used"].timestamp() if r["last_used"] else 0.0), r["tag"]))
        assert [r["tag"] for r in rows] == ["new", "old", "never"]

    async def test_sorting_actually_changes_the_order(self, member_client, async_db, tag_data):
        """End to end, through the route the control calls."""
        by_name = (await member_client.get("/intel/tags?sort=name", headers={"HX-Request": "true"})).text
        by_recent = (await member_client.get("/intel/tags?sort=recent", headers={"HX-Request": "true"})).text
        assert by_name != by_recent, "the two orderings must differ"

    async def test_the_filter_controls_do_not_resend_each_others_stale_values(self, member_client, tag_data):
        """`hx-include="closest .lt-bar"` reached the create form's hidden q/sort carriers.

        htmx walks into a nested <form> when the include target is not itself a form, so
        every request carried each value twice — live then stale — and Starlette keeps the
        last. Changing the sort re-sent the sort you already had.
        """
        body = (await member_client.get("/intel/tags")).text
        assert 'hx-include="closest .lt-bar"' not in body
        assert 'hx-include="#tagmgr-sort"' in body
        assert 'hx-include="#tagmgr-q"' in body

    async def test_merge_offers_the_whole_vocabulary(self, member_client, tag_data):
        """Built from the *filtered, capped* page, the candidates would vanish exactly when
        you search for the tag you want to merge away — and a native datalist shows nothing
        until you type and carries no colour."""
        body = (await member_client.get("/intel/tags")).text
        assert "known-tags" not in body, "the page-scoped datalist is gone"
        assert 'name="into"' in body
        # The combobox fetches the vocabulary itself rather than being seeded from the page.
        assert "tagCombobox()" in body

    async def test_no_ancestor_clips_the_dropdowns(self, member_client, tag_data):
        """The rows sat inside `rounded-xl overflow-hidden`, which clips an absolutely
        positioned panel. The combobox panel is ~224px against a ~36px row, so on the last
        row — and on a one-tag table, which is what the fixtures render — it opened into
        nothing."""
        # Read the partial, not the page: base.html's own <style> block *documents* the
        # overflow-hidden rule in a comment, and a whole-page substring search finds that.
        body = (await member_client.get("/intel/tags", headers={"HX-Request": "true"})).text
        assert "overflow-hidden" not in body, "an ancestor still clips the row dropdowns"


class TestPageChrome:
    """One rule for getting back, applied everywhere.

    There were three idioms across nineteen templates — `← Home`, `← Admin`, and an
    `Admin / Page` breadcrumb — with no rule about which belonged where, so "how do I get
    back" had a different answer depending on where you happened to be.

    The rule: a page **in the nav** goes to Home; a **section sub-page** goes to its section.
    """

    async def test_every_nav_level_page_goes_home(self, member_client, admin_client, tag_data):
        for client, urls in (
            (member_client, ["/jobs", "/intel", "/intel/tags", "/intel/cases"]),
            (admin_client, ["/admin"]),
        ):
            for url in urls:
                body = (await client.get(url)).text
                assert "&larr; Home" in body, f"{url} has no way back to Home"

    async def test_every_admin_sub_page_goes_to_the_manage_tab(self, admin_client):
        """`/admin` alone lands on Overview — the tab you left from is Manage. It works
        because `resourceTabs.init()` reads `location.hash` on load; it would NOT work as a
        same-document link, since the component registers no `hashchange` listener."""
        for url in (
            "/admin/users",
            "/admin/workers",
            "/admin/storage",
            "/admin/ai",
            "/admin/enrichment",
            "/admin/api-tokens",
            "/admin/activity",
            "/admin/tasks",
            "/admin/settings",
        ):
            body = (await admin_client.get(url)).text
            assert 'href="/admin#manage"' in body, f"{url} does not return to the Manage tab"
            assert "&larr; Manage" in body, f"{url} uses a different back idiom"

    def test_no_template_still_points_at_the_admin_overview(self):
        """`← Admin` is the idiom the macro replaced, and it went to the wrong tab.

        A *detail* page's breadcrumb is deliberately left alone — `Intel / IP Address /
        1.2.3.4` is a location trail whose middle segment is a working filter pivot, which is
        a different thing from "how do I get back" and is asserted by its own test.
        """
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent / "app" / "templates"
        offenders = [p.name for p in root.rglob("*.html") if "&larr; Admin" in p.read_text()]
        assert not offenders, f"these still point at the Admin overview instead of the Manage tab: {offenders}"


class TestATagWithASlash:
    """`mitre/t1059` and `c2/cobalt` are natural tags, and writing one succeeds. Every control
    that acted on it afterwards 404'd: the tag rides in the URL path, Jinja's `urlencode`
    leaves `/` alone, and the routes took one path segment. Even `%2F` could not help —
    Starlette decodes the path before routing. The URLs here are scraped from the rendered
    page, so they are the ones a browser would send."""

    @pytest.fixture()
    async def slashed(self, async_db, tag_data):
        async_db.add(EntityTag(entity_id=tag_data["c"].id, tag="mitre/t1059", color="red"))
        await async_db.commit()
        return tag_data

    async def _url(self, member_client, verb):
        import re

        body = (await member_client.get("/intel/tags?q=mitre")).text
        match = re.search(rf'hx-post="(/intel/tags/{verb})"', body)
        assert match, f"no {verb} control rendered for the tag"
        return match.group(1)

    async def test_rename(self, member_client, async_db, slashed):
        resp = await member_client.post(await self._url(member_client, "rename"), data={"tag": "mitre/t1059", "new_tag": "mitre-t1059"})
        assert resp.status_code == 200
        assert await _count(async_db, "mitre/t1059") == 0
        assert await _count(async_db, "mitre-t1059") == 1

    async def test_recolor(self, member_client, async_db, slashed):
        assert (await member_client.post(await self._url(member_client, "recolor"), data={"tag": "mitre/t1059", "color": "purple"})).status_code == 200
        assert (await async_db.execute(select(EntityTag.color).where(EntityTag.tag == "mitre/t1059"))).scalars().all() == ["purple"]

    async def test_merge(self, member_client, async_db, slashed):
        assert (await member_client.post(await self._url(member_client, "merge"), data={"tag": "mitre/t1059", "into": "gamma"})).status_code == 200
        assert await _count(async_db, "mitre/t1059") == 0

    async def test_delete(self, member_client, async_db, slashed):
        assert (await member_client.post(await self._url(member_client, "delete"), data={"tag": "mitre/t1059"})).status_code == 200
        assert await _count(async_db, "mitre/t1059") == 0

    async def test_remove_from_the_entity_header(self, member_client, async_db, slashed):
        import re

        entity_id = slashed["c"].id
        body = (await member_client.get(f"/intel/entities/{entity_id}")).text
        url = re.search(r'hx-post="(/intel/entities/\d+/tags/remove)"', body).group(1)
        assert (await member_client.post(url, data={"tag": "mitre/t1059"})).status_code == 200
        assert await _count(async_db, "mitre/t1059") == 0
