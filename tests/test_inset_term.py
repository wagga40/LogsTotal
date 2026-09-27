"""`in:(a,b,c)` — a list too small to deserve a name.

The named kind earns its keep when a set is shared between rules, described, or long.
Spelling out two binaries should not require creating and naming a row first, and it did.

It is the anonymous form of `list:`, so it matches the same way `list:` does at its default
match kind: **exact**, not substring (a bare term already gives that) and not suffix
(`(*.tk OR *.top)` already gives that).
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.intel.queries import MAX_INSET_VALUES, apply_entity_filters, parse_query, scan_query
from app.models import Entity

pytestmark = pytest.mark.anyio


class TestParsing:
    def test_it_reads_a_set(self):
        term = parse_query("in:(psexec.exe,wmic.exe)")["terms"][0]
        assert term["kind"] == "inset"
        assert term["values"] == ["psexec.exe", "wmic.exe"]

    def test_it_lowercases_trims_and_dedupes_like_the_write_path(self):
        term = parse_query("in:( PsExec.exe , wmic.exe ,psexec.EXE )")["terms"][0]
        assert term["values"] == ["psexec.exe", "wmic.exe"]

    def test_it_can_be_negated(self):
        term = parse_query("-in:(a,b)")["terms"][0]
        assert term["kind"] == "inset" and term["negated"] is True

    def test_it_survives_a_second_term(self):
        """A prefix missing from `_PREFIXES` parses alone and is swallowed into a
        whole-phrase literal the moment the query has two terms."""
        kinds = [t["kind"] for t in parse_query("in:(a,b) tag:x")["terms"]]
        assert kinds == ["inset", "tag"]

    @pytest.mark.parametrize(
        ("raw", "fragment"),
        [
            ("in:foo", "parenthesised"),
            ("in:()", "at least one"),
            ("in:(" + ",".join(str(n) for n in range(MAX_INSET_VALUES + 1)) + ")", "at most"),
        ],
    )
    def test_it_explains_itself_rather_than_raising(self, raw, fragment):
        term = parse_query(raw)["terms"][0]
        assert term["kind"] == "literal"
        assert fragment in term["error"]


class TestTheScanner:
    def test_the_set_is_one_token_parens_and_all(self):
        assert scan_query("in:(a,b) tag:x") == [(0, 8, "in:(a,b)"), (9, 14, "tag:x")]

    def test_its_parens_never_reach_the_boolean_parser(self):
        """Its own scanner pass, for the reason `re:/…/` has one: the generic walk ends a
        term at a parenthesis under `split_groups`, which would shred one valid set into
        junk *and* feed its `(` to the grouping rules."""
        assert scan_query("(in:(a,b) OR tag:x)", split_groups=True) == [
            (0, 1, "("),
            (1, 9, "in:(a,b)"),
            (10, 12, "OR"),
            (13, 18, "tag:x"),
            (18, 19, ")"),
        ]

    def test_a_set_inside_a_group_still_parses_as_a_set(self):
        kinds = [t["kind"] for t in parse_query("(in:(a,b) OR tag:x) -tag:z")["terms"]]
        assert kinds == ["inset", "tag", "tag"]


class TestAgainstTheDatabase:
    @pytest.fixture()
    async def entities(self, async_db):
        for value, kind in [
            ("psexec.exe", "executable"),
            ("wmic.exe", "executable"),
            ("PSEXEC.EXE", "cmdline_file"),
            ("notpsexec.exe", "executable"),
            ("svchost.exe", "executable"),
        ]:
            async_db.add(Entity(value=value, entity_type=kind))
        await async_db.commit()

    async def _values(self, async_db, query: str) -> set[str]:
        stmt = apply_entity_filters(select(Entity), query=parse_query(query))
        return {r.value for r in (await async_db.execute(stmt)).scalars().all()}

    async def test_it_matches_the_whole_value_not_a_substring(self, async_db, entities):
        """`notpsexec.exe` contains `psexec.exe`; a bare term would return it and this
        must not, or `in:` is just a slower way to write an OR of literals."""
        assert await self._values(async_db, "in:(psexec.exe)") == {"psexec.exe", "PSEXEC.EXE"}

    async def test_it_is_case_insensitive_on_both_sides(self, async_db, entities):
        assert await self._values(async_db, "in:(PSEXEC.EXE)") == {"psexec.exe", "PSEXEC.EXE"}

    async def test_several_values_are_a_union(self, async_db, entities):
        assert await self._values(async_db, "in:(psexec.exe,svchost.exe)") == {"psexec.exe", "PSEXEC.EXE", "svchost.exe"}

    async def test_negation_excludes(self, async_db, entities):
        got = await self._values(async_db, "-in:(psexec.exe,svchost.exe)")
        assert got == {"wmic.exe", "notpsexec.exe"}

    async def test_it_may_sit_under_an_or(self, async_db, entities):
        """Unlike `re:`/`cidr:`, which are post-filtered and rejected under OR. The values
        are known at parse time and compile to a plain IN — the same thing that makes
        `list:` OR-safe."""
        parsed = parse_query("(in:(psexec.exe) OR in:(svchost.exe))")
        assert not parsed.get("invalid"), parsed.get("invalid")
        assert await self._values(async_db, "(in:(psexec.exe) OR in:(svchost.exe))") == {
            "psexec.exe",
            "PSEXEC.EXE",
            "svchost.exe",
        }

    async def test_it_narrows_in_sql_rather_than_in_python(self, async_db, entities):
        """If it were post-filtered, the count query would be wrong — the jobs list and the
        rules dry-run both compile the same builder against `select(count())`."""
        from app.intel.queries import query_needs_post_filter

        assert not query_needs_post_filter(parse_query("in:(a,b)"))
        stmt = apply_entity_filters(select(func.count(Entity.id)), query=parse_query("in:(psexec.exe)"))
        assert (await async_db.execute(stmt)).scalar_one() == 2


class TestTheClientAgrees:
    """Three tokenizers understand `in:(…)` and they must agree about where it ends.

    The server's, the graph client's (a deliberate port — filtering a graph you are already
    looking at costs no round trip) and the condition editor's highlighter. A cap that
    differs between them shows up as a query the field accepts and the server refuses.
    """

    def _js_const(self, path: str, name: str) -> int:
        import re
        from pathlib import Path

        m = re.search(rf"const {name} = (\d+);", Path(path).read_text())
        assert m, f"{name} not found in {path}"
        return int(m.group(1))

    def test_the_graph_client_caps_where_the_parser_does(self):
        assert self._js_const("app/static/graph-view.js", "MAX_INSET_VALUES") == MAX_INSET_VALUES

    def test_the_prefix_is_advertised_so_a_query_reads_as_structured(self):
        """A prefix missing from `_PREFIXES` parses alone and is swallowed into a
        whole-phrase literal the moment the query has two terms."""
        from app.intel.queries import _PREFIXES

        assert "in:" in _PREFIXES

    def test_the_editor_can_colour_it(self):
        """`condition_grammar` ships `_PREFIXES`, so this follows from the line above — but
        it is the thing an analyst actually sees, and it is worth failing on directly."""
        from app.templates_config import templates

        assert "in:" in templates.env.globals["condition_grammar"]["entity"]["prefixes"]


class TestPromotingASetToAList:
    """`in:(a,b,c)` → a named list, and the rule repointed at it, in one action.

    Two halves that are useless apart: a list nothing references is clutter, and a rule
    still spelling the set out has not been promoted.
    """

    @pytest.fixture()
    async def a_rule_with_a_set(self, async_db):
        from app.models import IntelRule

        rule = IntelRule(name="Remote exec", query="in:(psexec.exe,wmic.exe) -tag:known-good", is_builtin=True, scope="entity")
        async_db.add(rule)
        await async_db.commit()
        await async_db.refresh(rule)
        return rule

    async def test_it_creates_the_list_and_repoints_the_rule(self, admin_client, async_db, a_rule_with_a_set):
        from app.intel.rule_lists import load_lists
        from app.models import IntelRule

        resp = await admin_client.post(
            f"/intel/rules/{a_rule_with_a_set.id}/promote-set",
            data={"name": "remote_exec", "description": "Remote execution tools"},
        )
        assert resp.status_code == 200

        lists = {spec.name: spec for _row, spec in await load_lists(async_db)}
        assert "remote_exec" in lists
        assert set(lists["remote_exec"].values) == {"psexec.exe", "wmic.exe"}
        assert lists["remote_exec"].match == "exact", "a set is exact; that is what `in:` means"

        await async_db.refresh(a_rule_with_a_set)
        rule = await async_db.get(IntelRule, a_rule_with_a_set.id)
        assert rule.query == "list:remote_exec -tag:known-good"

    async def test_it_rewrites_in_place_leaving_the_other_terms_alone(self, admin_client, async_db):
        """The scanner gives the term's own span, so the rest of the condition — including
        its order — comes through untouched."""
        from app.models import IntelRule

        rule = IntelRule(name="Mixed", query="type:executable in:(x,y) -tag:known-good", is_builtin=True, scope="entity")
        async_db.add(rule)
        await async_db.commit()
        await async_db.refresh(rule)

        await admin_client.post(f"/intel/rules/{rule.id}/promote-set", data={"name": "xy", "description": ""})
        assert (await async_db.get(IntelRule, rule.id)).query == "type:executable list:xy -tag:known-good"

    async def test_a_negated_set_stays_negated(self, admin_client, async_db):
        from app.models import IntelRule

        rule = IntelRule(name="Not these", query="-in:(a,b)", is_builtin=True, scope="entity")
        async_db.add(rule)
        await async_db.commit()
        await async_db.refresh(rule)

        await admin_client.post(f"/intel/rules/{rule.id}/promote-set", data={"name": "ab", "description": ""})
        assert (await async_db.get(IntelRule, rule.id)).query == "-list:ab"

    async def test_a_member_may_not_promote(self, member_client, a_rule_with_a_set):
        """A list is instance-wide, while the set it came from was the rule owner's alone.
        That asymmetry is why this is a separate verb and not part of saving a rule."""
        resp = await member_client.post(f"/intel/rules/{a_rule_with_a_set.id}/promote-set", data={"name": "nope", "description": ""})
        assert resp.status_code == 403

    async def test_a_name_already_taken_is_refused(self, admin_client, async_db, a_rule_with_a_set):
        from app.intel.rule_lists import ListSpec, write_list

        await write_list(async_db, None, ListSpec(name="taken", values=("x",)), seed_hash=None)
        await async_db.commit()

        resp = await admin_client.post(f"/intel/rules/{a_rule_with_a_set.id}/promote-set", data={"name": "taken", "description": ""})
        assert resp.status_code == 400
        assert (await async_db.get(type(a_rule_with_a_set), a_rule_with_a_set.id)).query.startswith("in:("), "the rule must be untouched when the list could not be made"

    async def test_a_rule_with_two_sets_is_refused(self, admin_client, async_db):
        """Which one becomes a list is a judgement the analyst makes, in the form."""
        from app.models import IntelRule

        rule = IntelRule(name="Two", query="in:(a,b) in:(c,d)", is_builtin=True, scope="entity")
        async_db.add(rule)
        await async_db.commit()
        await async_db.refresh(rule)

        resp = await admin_client.post(f"/intel/rules/{rule.id}/promote-set", data={"name": "one", "description": ""})
        assert resp.status_code == 400

    async def test_a_promoted_shared_rule_stops_tracking_the_file(self, admin_client, async_db, a_rule_with_a_set):
        """Rewriting the condition is an edit like any other, and the seeder must leave an
        edited row alone from then on."""
        await admin_client.post(f"/intel/rules/{a_rule_with_a_set.id}/promote-set", data={"name": "remote_exec", "description": ""})
        assert (await async_db.get(type(a_rule_with_a_set), a_rule_with_a_set.id)).seed_hash is None


def test_quoting_does_not_make_a_prefix_literal():
    """Recorded because it surprised a test, not because it is new.

    The scanner strips a quoted run's quotes before the term parser sees it, so `"tag:x"`
    has always parsed as a tag term rather than as the literal string. `in:` inherits that,
    which is why a condition carrying `"in:(a,b)" in:(x,y)` genuinely holds *two* sets and
    is correctly refused promotion rather than being a case the rewriter must be clever
    about.

    Quotes exist here for phrases with spaces (`"exact phrase"`). Changing what they do to
    a prefix would silently change the meaning of every rule already written with one, so
    this pins the behaviour rather than proposing it.
    """
    assert [t["kind"] for t in parse_query('"tag:x"')["terms"]] == ["tag"]
    assert [t["kind"] for t in parse_query('"in:(a,b)"')["terms"]] == ["inset"]
    assert [t["kind"] for t in parse_query('"an exact phrase"')["terms"]] == ["literal"]
