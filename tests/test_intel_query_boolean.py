"""Tier-1 tests for the `job:` term and the boolean (AND/OR/parens) query grammar.

Two properties matter more than the features themselves:

**Nothing already stored may change meaning.** Saved searches and `IntelRule.query` are
kept as raw text and re-parsed on every use, so a grammar that reinterpreted them would
silently change which entities an existing alert fires on. Operators are therefore bare
uppercase words only, and parentheses group only in an already-structured query.

**`re:`/`cidr:` may not sit under an OR.** They contribute no SQL and are matched in Python
over the rows SQL returned. As an AND conjunct that is sound (those rows are a superset);
under an OR the branch would have to contribute rows nothing fetched, so results would be
quietly incomplete. The parser rejects it instead.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import sqlite

from app.intel.queries import (
    CIDR_QUERY_MAX,
    JOB_QUERY_MAX,
    MAX_GROUP_DEPTH,
    apply_entity_filters,
    job_terms,
    list_terms,
    parse_query,
    post_filter,
    query_needs_post_filter,
    resolve_job_terms,
    unknown_list_errors,
)
from app.models import Entity


def _sql(raw: str, visible: set[int] | None = None) -> str:
    parsed = parse_query(raw)
    if visible is not None:
        resolve_job_terms(parsed, visible)
    stmt = apply_entity_filters(select(Entity.id), query=parsed)
    return " ".join(str(stmt.compile(dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True})).split())


def _kinds(raw: str) -> list[str]:
    return [t.get("kind") for t in parse_query(raw)["terms"]]


# ── back-compat: stored queries must parse exactly as before ────────────────────────


@pytest.mark.parametrize(
    "raw",
    [
        "powershell (encoded)",  # parens, but no structured syntax → still a phrase
        "foo or bar",  # lowercase, so not an operator
        "foo and bar",
        "powershell -enc",  # a bare leading '-' is part of the phrase, not a negation
        "(just parens)",
        "and",
        "or",
    ],
)
def test_unstructured_queries_stay_one_literal_phrase(raw):
    parsed = parse_query(raw)
    assert parsed["tree"] is None, f"{raw!r} must not enter boolean mode"
    assert parsed["terms"] == [{"kind": "literal", "raw": raw, "value": raw, "negated": False}], f"{raw!r} changed meaning"


@pytest.mark.parametrize(
    "raw",
    [
        "tag:a tag:b",
        "re:/^svc/ tag:x",
        "cidr:10.0.0.0/8 label:lolbin",
        "label:lolbin -tag:noisy",
        '-"enc" tag:a',
    ],
)
def test_existing_conjunctions_keep_the_flat_path(raw):
    """No OR means no tree, so post_filter and the tag folding run their original code."""
    assert parse_query(raw)["tree"] is None


def test_lowercase_or_is_not_an_operator_even_when_structured():
    parsed = parse_query("tag:a or tag:b")
    assert parsed["tree"] is None
    assert _kinds("tag:a or tag:b") == ["tag", "literal", "tag"], "the bare word 'or' must stay a search term"


# ── job: ────────────────────────────────────────────────────────────────────────────


def test_job_term_parses_single_and_csv():
    assert _kinds("job:42") == ["job"]
    assert parse_query("job:42")["terms"][0]["job_ids"] == [42]
    assert parse_query("job:3,1,3,2")["terms"][0]["job_ids"] == [3, 1, 2], "ids dedupe, order preserved"


def test_job_term_rejects_non_numeric_ids():
    parsed = parse_query("job:abc")
    assert parsed["terms"][0]["kind"] == "literal"
    assert "numeric" in parsed["errors"][0]


@pytest.mark.parametrize("raw", ["job:²", "job:①", "job:99999999999999999999"])
def test_job_term_rejects_ids_the_database_cannot_take(raw):
    """A superscript digit passes `isdigit()` and then raises in `int()`; an id past int4 is
    a bind error on PostgreSQL. Both reached the Intel dashboard as a 500."""
    parsed = parse_query(raw)
    assert parsed["terms"][0]["kind"] == "literal"
    assert parsed["errors"]


def test_job_ids_are_capped():
    parsed = parse_query("job:" + ",".join(str(i) for i in range(1, JOB_QUERY_MAX + 6)))
    assert len(parsed["terms"][0]["job_ids"]) == JOB_QUERY_MAX


def test_an_unresolved_job_term_matches_nothing():
    """Failing closed is the point: forgetting `resolve_job_terms` must not leak a job."""
    parsed = parse_query("job:42")
    assert not parsed["terms"][0]["resolved"]
    assert "0 = 1" in _sql("job:42"), "an unchecked job term must not become a real filter"


def test_a_visible_job_becomes_a_real_filter():
    assert "entity_job_link.job_id IN (42)" in _sql("job:42", visible={42})


def test_an_invisible_job_matches_nothing_rather_than_being_dropped():
    """Dropping it would turn `tag:x job:<private>` into a plain `tag:x` and present the
    result as though it came from that job."""
    assert "0 = 1" in _sql("job:42", visible=set())
    assert "0 = 1" in _sql("tag:x job:42", visible=set())


def test_resolve_reports_whether_anything_was_dropped():
    parsed = parse_query("job:1,2,3")
    assert resolve_job_terms(parsed, {1, 3}) is True
    assert parsed["terms"][0]["job_ids"] == [1, 3]

    ok = parse_query("job:1,2")
    assert resolve_job_terms(ok, {1, 2}) is False


def test_job_terms_finds_them_inside_a_boolean_tree():
    parsed = parse_query("label:lolbin AND (job:7 OR job:9)")
    assert sorted(i for t in job_terms(parsed) for i in t["job_ids"]) == [7, 9]


# ── boolean grammar ─────────────────────────────────────────────────────────────────


def test_or_builds_a_tree_and_disjunctive_sql():
    sql = _sql("tag:a OR tag:b")
    assert " OR " in sql
    assert parse_query("tag:a OR tag:b")["tree"]["op"] == "or"


def test_explicit_and_matches_juxtaposition():
    assert _sql("tag:a AND tag:b") == _sql("tag:a tag:b")


def test_and_binds_tighter_than_or():
    """`a OR b c` is `a OR (b AND c)`, the conventional precedence."""
    tree = parse_query("tag:a OR tag:b tag:c")["tree"]
    assert tree["op"] == "or"
    assert [n.get("op") or n["kind"] for n in tree["nodes"]] == ["tag", "and"]


def test_parentheses_override_precedence():
    sql = _sql("(tag:a OR tag:b) -tag:c")
    # The disjunction is bracketed and the negation applies to the whole group, not to b.
    assert sql.index(" OR ") < sql.index("NOT")
    assert "AND NOT" in sql


def test_group_only_counts_when_the_query_is_already_structured():
    assert parse_query("tag:a (tag:b OR tag:c)")["tree"] is not None
    assert parse_query("plain (words here)")["tree"] is None


def test_unbalanced_parentheses_are_reported_not_crashed():
    for raw in ("(tag:a OR tag:b", "tag:a) OR tag:b", "((tag:a OR tag:b)"):
        parsed = parse_query(raw)
        assert any("unbalanced" in e for e in parsed["errors"]), f"{raw!r} produced {parsed['errors']}"


def test_deep_nesting_is_bounded():
    raw = "tag:z AND " + "(" * (MAX_GROUP_DEPTH + 3) + "tag:a" + ")" * (MAX_GROUP_DEPTH + 3)
    parsed = parse_query(raw)
    assert any("nested" in e for e in parsed["errors"])


def test_a_regex_inside_a_group_containing_no_or_is_still_fine():
    parsed = parse_query("(re:/^svc/ tag:a)")
    assert not parsed.get("invalid")


# ── the OR / post-filter rejection ──────────────────────────────────────────────────


@pytest.mark.parametrize("raw", ["re:/^svc/ OR tag:x", "cidr:10.0.0.0/8 OR tag:x", "tag:x OR (tag:y OR re:/^a/)"])
def test_post_filtered_terms_are_rejected_under_or(raw):
    parsed = parse_query(raw)
    assert parsed["invalid"], f"{raw!r} should be rejected"
    assert any("cannot be combined with OR" in e for e in parsed["errors"])


def test_a_rejected_query_matches_nothing_rather_than_something_plausible():
    assert "0 = 1" in _sql("re:/^svc/ OR tag:x")


def test_a_rejected_query_skips_the_post_filter_fetch():
    assert query_needs_post_filter(parse_query("re:/^svc/ OR tag:x")) is False


def test_post_filtered_terms_are_allowed_as_and_conjuncts_of_an_or():
    """`re:` ANDed over a disjunction is sound — SQL returns the OR superset and the regex
    narrows it in Python, exactly as it does for a flat conjunction."""
    parsed = parse_query("re:/^svc/ AND (tag:a OR tag:b)")
    assert not parsed["invalid"]
    assert query_needs_post_filter(parsed) is True
    sql = _sql("re:/^svc/ AND (tag:a OR tag:b)")
    assert " OR " in sql and "0 = 1" not in sql


def test_an_empty_branch_does_not_widen_the_query_to_everything():
    """A branch contributing no SQL must collapse, not render as literal TRUE inside an OR."""
    sql = _sql("tag:a OR tag:b")
    assert "1 = 1" not in sql


# ── type: ───────────────────────────────────────────────────────────────────────────


def test_type_term_accepts_canonical_keys():
    from app.constants import ENTITY_TYPES

    for key in ENTITY_TYPES:
        parsed = parse_query(f"type:{key}")
        assert parsed["terms"][0]["kind"] == "type", f"type:{key} did not parse"
        assert parsed["terms"][0]["types"] == [key]


def test_type_term_accepts_the_documented_aliases():
    assert parse_query("type:ip")["terms"][0]["types"] == ["ip_address"]
    assert parse_query("type:exe")["terms"][0]["types"] == ["executable"]
    assert parse_query("type:cmdline")["terms"][0]["types"] == ["cmdline_file"]


def test_type_term_is_any_of_and_dedupes():
    assert parse_query("type:domain,user,domain")["terms"][0]["types"] == ["domain", "user"]


def test_type_term_is_case_insensitive():
    assert parse_query("type:IP_Address")["terms"][0]["types"] == ["ip_address"]


def test_unknown_type_errors_and_lists_the_valid_ones():
    parsed = parse_query("type:bogus")
    assert parsed["terms"][0]["kind"] == "literal"
    assert "unknown type" in parsed["errors"][0]
    assert "ip_address" in parsed["errors"][0], "the error should name the options"


def test_empty_type_errors():
    assert "needs an entity type" in parse_query("type:")["errors"][0]


def test_type_term_compiles_to_an_entity_type_filter():
    assert "entity.entity_type IN ('ip_address')" in _sql("type:ip")


def test_type_term_composes_with_or_and_negation():
    assert " OR " in _sql("type:domain OR type:user")
    assert "NOT" in _sql("-type:domain")


def test_type_is_sql_expressible_so_it_needs_no_post_filter():
    assert query_needs_post_filter(parse_query("type:ip OR type:domain")) is False


def test_the_type_registry_matches_the_dashboard_badge_map():
    """`queries.py` validates against `constants.ENTITY_TYPES` while the router renders
    labels and colours from `ENTITY_TYPE_META`. A key in one and not the other is either an
    unsearchable type or a searchable one that renders with no badge."""
    from app.constants import ENTITY_TYPE_META, ENTITY_TYPES

    assert tuple(ENTITY_TYPE_META.keys()) == ENTITY_TYPES


# ── list: ───────────────────────────────────────────────────────────────────────────


def test_list_term_carries_a_name_and_nothing_else():
    """The parser is pure; the lists live in the database. Resolution is the SQL's."""
    term = parse_query("list:LOLBAS")["terms"][0]
    assert term == {"kind": "list", "raw": "list:LOLBAS", "name": "lolbas", "negated": False}


def test_list_compiles_to_an_exists_over_the_list_tables():
    sql = _sql("list:gtfobins")
    assert "EXISTS" in sql and "rule_list.name = 'gtfobins'" in sql
    # Both kinds in one clause, so the parser never needs to know which the list is.
    assert "rule_list.\"match\" = 'exact'" in sql and "rule_list.\"match\" = 'suffix'" in sql
    assert "lower(entity.value)" in sql and "LIKE rule_list_value.pattern" in sql


def test_list_is_sql_so_it_may_sit_under_or_and_needs_no_post_filter():
    parsed = parse_query("list:lolbas OR tag:x")
    assert not parsed.get("invalid")
    assert query_needs_post_filter(parsed) is False
    assert " OR " in _sql("list:lolbas OR tag:x")


def test_list_negates():
    assert "NOT (EXISTS" in _sql("-list:lolbas")


def test_a_list_the_database_lacks_is_the_callers_error_to_raise():
    parsed = parse_query("list:nope tag:a")
    assert parsed["errors"] == []
    assert unknown_list_errors(parsed, {"lolbas", "gtfobins"}) == ["unknown list: nope — try gtfobins, lolbas"]
    assert unknown_list_errors(parsed, set()) == ["unknown list: nope — no lists are defined yet"]
    assert unknown_list_errors(parse_query("list:lolbas"), {"lolbas"}) == []
    assert list_terms(parse_query("list:a list:b -list:a")) == ["a", "b"]


def test_list_takes_one_name_and_a_well_formed_one():
    assert any("one per term" in e for e in parse_query("list:lolbas,gtfobins")["errors"])
    assert any("one per term" in e for e in parse_query("list:Bad-Name")["errors"])


def test_empty_list_name_errors():
    assert any("needs a list name" in e for e in parse_query("list:")["errors"])


# ── cidr: comma lists ───────────────────────────────────────────────────────────────


def _ip(i, value):
    return Entity(id=i, value=value, entity_type="ip_address")


def test_cidr_comma_list_is_any_of_in_sql_and_in_python():
    parsed = parse_query("cidr:10.0.0.0/8,192.168.0.0/16")
    assert [str(n) for n in parsed["terms"][0]["networks"]] == ["10.0.0.0/8", "192.168.0.0/16"]
    sql = _sql("cidr:10.0.0.0/8,192.168.0.0/16")
    assert "'10.%'" in sql and "'192.168.%'" in sql and " OR " in sql
    rows = [_ip(1, "10.1.2.3"), _ip(2, "192.168.1.1"), _ip(3, "8.8.8.8")]
    assert [e.id for e in post_filter(rows, parsed)] == [1, 2]


def test_a_network_with_no_coarse_prefix_disables_the_prefix_prefilter_for_the_whole_term():
    """`::1/128` has no textual prefix; keeping the v4 prefixes would exclude it."""
    sql = _sql("cidr:127.0.0.0/8,::1/128")
    assert "LIKE" not in sql and "entity_type = 'ip_address'" in sql


def test_negated_cidr_list_means_in_none_of_them():
    parsed = parse_query("-cidr:10.0.0.0/8,192.168.0.0/16")
    rows = [_ip(1, "10.1.2.3"), _ip(2, "8.8.8.8"), Entity(id=3, value="evil.exe", entity_type="executable")]
    assert [e.id for e in post_filter(rows, parsed)] == [2, 3]


def test_cidr_list_is_capped():
    too_many = "cidr:" + ",".join(f"10.{i}.0.0/16" for i in range(CIDR_QUERY_MAX + 1))
    assert any("at most" in e for e in parse_query(too_many)["errors"])
    just_enough = "cidr:" + ",".join(f"10.{i}.0.0/16" for i in range(CIDR_QUERY_MAX))
    assert not parse_query(just_enough)["errors"]


def test_one_bad_network_fails_the_whole_cidr_term():
    assert any("invalid CIDR" in e for e in parse_query("cidr:10.0.0.0/8,nonsense")["errors"])
