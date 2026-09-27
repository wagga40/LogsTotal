"""Tier-1 tests for the entity query parser and post-filter helpers."""

from __future__ import annotations

import ipaddress
import time

import regex

from app.intel.queries import (
    QUERY_KINDS,
    REGEX_MAX_LEN,
    TAG_QUERY_MAX,
    parse_search_query,
    parse_since,
    parse_tags_csv,
    parse_types_csv,
    regex_post_filter,
)
from app.models import Entity


class TestParseSearchQuery:
    def test_empty_returns_literal_empty(self):
        r = parse_search_query("")
        assert r["kind"] == "literal"
        assert r["value"] == ""

    def test_literal_plain_text(self):
        r = parse_search_query("admin")
        assert r["kind"] == "literal"
        assert r["value"] == "admin"

    def test_wildcard_trailing(self):
        r = parse_search_query("foo*")
        assert r["kind"] == "wildcard"
        assert r["pattern"] == "%foo%"

    def test_wildcard_middle_and_escapes_sql_meta(self):
        r = parse_search_query("a*_b%")
        assert r["kind"] == "wildcard"
        # `_` and `%` should be escaped to literals
        assert r["pattern"].startswith("%")
        assert r["pattern"].endswith("%")
        assert "\\_" in r["pattern"]
        assert "\\%" in r["pattern"]

    def test_regex_compiled_case_insensitive(self):
        r = parse_search_query("re:/^admin/")
        assert r["kind"] == "regex"
        assert isinstance(r["pattern"], regex.Pattern)
        assert r["pattern"].flags & regex.IGNORECASE

    def test_regex_too_long_falls_back_to_literal(self):
        long_pat = "a" * (REGEX_MAX_LEN + 5)
        r = parse_search_query(f"re:/{long_pat}/")
        assert r["kind"] == "literal"
        assert "regex" in r.get("error", "")

    def test_regex_nested_quantifier_rejected(self):
        r = parse_search_query("re:/(a+)+/")
        assert r["kind"] == "literal"
        assert "nested" in r.get("error", "")

    def test_regex_invalid_syntax_falls_back(self):
        r = parse_search_query("re:/[unclosed/")
        assert r["kind"] == "literal"
        assert "invalid regex" in r.get("error", "")

    def test_cidr_ipv4(self):
        r = parse_search_query("cidr:10.0.0.0/16")
        assert r["kind"] == "cidr"
        assert r["networks"] == [ipaddress.IPv4Network("10.0.0.0/16")]

    def test_cidr_ipv6(self):
        r = parse_search_query("cidr:2001:db8::/32")
        assert r["kind"] == "cidr"
        assert r["networks"] == [ipaddress.IPv6Network("2001:db8::/32")]

    def test_cidr_bad_falls_back(self):
        r = parse_search_query("cidr:notvalid")
        assert r["kind"] == "literal"
        assert "invalid CIDR" in r.get("error", "")


class TestRegexPostFilter:
    def _e(self, value, etype="ip_address"):
        return Entity(id=1, value=value, entity_type=etype)

    def test_literal_passthrough(self):
        ents = [self._e("a"), self._e("b")]
        assert regex_post_filter(ents, {"kind": "literal", "value": ""}) == ents

    def test_regex_match(self):
        ents = [self._e("admin1"), self._e("user2"), self._e("admin2")]
        parsed = parse_search_query("re:/^admin/")
        kept = regex_post_filter(ents, parsed)
        assert [e.value for e in kept] == ["admin1", "admin2"]

    def test_cidr_match_ipv4(self):
        ents = [self._e("10.0.0.5"), self._e("192.168.1.1"), self._e("10.0.0.99")]
        parsed = parse_search_query("cidr:10.0.0.0/24")
        kept = regex_post_filter(ents, parsed)
        assert sorted(e.value for e in kept) == ["10.0.0.5", "10.0.0.99"]

    def test_cidr_skips_non_ip_entities(self):
        ents = [self._e("10.0.0.5"), self._e("admin", etype="user")]
        parsed = parse_search_query("cidr:10.0.0.0/24")
        kept = regex_post_filter(ents, parsed)
        assert [e.value for e in kept] == ["10.0.0.5"]

    def test_regex_backtracking_bypass_is_time_bounded(self):
        # `(a|aa)+$` slips past the nested-quantifier pre-check but is catastrophic.
        # The regex engine's timeout must bound the total scan instead of hanging.
        parsed = parse_search_query("re:/(a|aa)+$/")
        assert parsed["kind"] == "regex"
        evil_input = "a" * 60 + "!"
        ents = [self._e(evil_input, etype="user") for _ in range(50)]
        start = time.monotonic()
        regex_post_filter(ents, parsed)
        elapsed = time.monotonic() - start
        # Comfortably above the 0.25s budget but far below an un-bounded hang.
        assert elapsed < 3.0


class TestParseSince:
    def test_iso_date(self):
        d = parse_since("2026-05-01")
        assert d is not None
        assert d.year == 2026 and d.month == 5 and d.day == 1

    def test_iso_datetime(self):
        d = parse_since("2026-05-01T12:30:00")
        assert d is not None
        assert d.hour == 12 and d.minute == 30

    def test_invalid_returns_none(self):
        assert parse_since("not-a-date") is None

    def test_empty_returns_none(self):
        assert parse_since("") is None


class TestParseTypesCsv:
    def test_keeps_only_valid_types(self):
        valid = {"ip_address", "user", "hash"}
        result = parse_types_csv("ip_address,user,bogus,hash", valid)
        assert result == ["ip_address", "user", "hash"]

    def test_empty_returns_empty(self):
        assert parse_types_csv("", {"ip_address"}) == []


class TestAttrQuery:
    def test_attr_lolbin_parses_to_attr_kind(self):
        r = parse_search_query("attr:lolbin")
        assert r["kind"] == "attr"
        assert r["fragment"] == '"is_lolbin":true'

    def test_attr_private(self):
        r = parse_search_query("attr:private")
        assert r["kind"] == "attr"
        assert r["fragment"] == '"is_private":true'

    def test_attr_gtfobin_parses_to_attr_kind(self):
        r = parse_search_query("attr:gtfobin")
        assert r["kind"] == "attr"
        assert r["fragment"] == '"is_gtfobin":true'

    def test_attr_md5(self):
        r = parse_search_query("attr:md5")
        assert r["fragment"] == '"algorithm":"md5"'

    def test_attr_public_category(self):
        r = parse_search_query("attr:public")
        assert r["fragment"] == '"category":"public"'

    def test_attr_suspicious_alias(self):
        r = parse_search_query("attr:suspicious")
        assert r["kind"] == "attr"
        assert r["fragment"] == '"suspicious_tld":true'

    def test_unknown_attr_falls_back_to_literal_with_error(self):
        r = parse_search_query("attr:bogus")
        assert r["kind"] == "literal"
        assert "error" in r

    def test_attr_fragment_matches_stored_json(self):
        # The fragment must be a substring of how attributes_json is actually serialized.
        from app.intel.attributes import compute_attributes
        from app.json_utils import dumps as json_dumps

        stored = json_dumps(compute_attributes("certutil.exe", "executable"))
        frag = parse_search_query("attr:lolbin")["fragment"]
        assert frag in stored


class TestTagQuery:
    def test_tag_prefix_parses_to_tag_kind(self):
        parsed = parse_search_query("tag:apt28")
        assert parsed["kind"] == "tag"
        assert parsed["tags"] == ["apt28"]

    def test_tag_prefix_normalizes_case_and_whitespace(self):
        """`tag:APT28` must match a tag stored lowercased by the write path."""
        assert parse_search_query("tag:  APT28  ")["tags"] == ["apt28"]

    def test_tag_prefix_multi_csv_dedupes_and_preserves_order(self):
        assert parse_search_query("tag:b,a,B,,a")["tags"] == ["b", "a"]

    def test_tag_prefix_caps_the_list(self):
        raw = "tag:" + ",".join(f"t{i}" for i in range(30))
        assert len(parse_search_query(raw)["tags"]) == TAG_QUERY_MAX

    def test_tag_prefix_empty_falls_back_to_literal_with_error(self):
        parsed = parse_search_query("tag:")
        assert parsed["kind"] == "literal"
        assert "tag:" in parsed["error"]

    def test_tag_is_a_known_query_kind(self):
        assert "tag" in QUERY_KINDS


class TestParseTagsCsv:
    def test_empty_is_empty(self):
        assert parse_tags_csv("") == []
        assert parse_tags_csv(None) == []

    def test_normalizes_dedupes_and_caps(self):
        assert parse_tags_csv(" Apt28 , apt28 , Ransomware ") == ["apt28", "ransomware"]
        assert len(parse_tags_csv(",".join(f"t{i}" for i in range(50)))) == TAG_QUERY_MAX

    def test_clamps_to_column_width(self):
        assert parse_tags_csv("x" * 200) == ["x" * 50]


# ── match_entity_rows (relationship-graph regex matching) ──────────────────


class _Row:
    def __init__(self, rid, value):
        self.id = rid
        self.value = value


def _rows(*pairs):
    return [_Row(i, v) for i, v in pairs]


def test_match_entity_rows_returns_ids_of_regex_matches():
    from app.intel.queries import match_entity_rows, parse_query

    rows = _rows((1, "svc-backup"), (2, "alice"), (3, "svc-web"))
    matched, partial = match_entity_rows(parse_query("re:/^svc-/"), rows)
    assert matched == {1, 3}
    assert partial is False


def test_match_entity_rows_is_case_insensitive_like_the_sql_path():
    from app.intel.queries import match_entity_rows, parse_query

    matched, _ = match_entity_rows(parse_query("re:/^SVC/"), _rows((1, "svc-backup")))
    assert matched == {1}


def test_match_entity_rows_honours_negation():
    from app.intel.queries import match_entity_rows, parse_query

    rows = _rows((1, "svc-backup"), (2, "alice"))
    matched, _ = match_entity_rows(parse_query("-re:/^svc-/ label:machine"), rows)
    assert matched == {2}


def test_match_entity_rows_ands_multiple_regex_terms():
    from app.intel.queries import match_entity_rows, parse_query

    rows = _rows((1, "svc-backup-01"), (2, "svc-web"), (3, "app-backup-01"))
    matched, _ = match_entity_rows(parse_query("re:/^svc-/ re:/01$/"), rows)
    assert matched == {1}


def test_match_entity_rows_ignores_non_regex_terms():
    """Everything else is evaluated client-side against decoded node attributes; a query
    with no regex must not accidentally filter the whole node set to nothing."""
    from app.intel.queries import match_entity_rows, parse_query

    rows = _rows((1, "a"), (2, "b"))
    assert match_entity_rows(parse_query("label:lolbin type:executable"), rows) == (set(), False)
    assert match_entity_rows(None, rows) == (set(), False)


def test_match_entity_rows_agrees_with_the_dashboard_post_filter():
    """Same corpus, same query, same answer — the graph and /intel must not disagree."""
    from app.intel.queries import match_entity_rows, parse_query, post_filter

    rows = _rows((1, "svc-backup"), (2, "alice"), (3, "svc-web"), (4, "SVC-DB"))
    query = parse_query("re:/^svc-/")
    assert match_entity_rows(query, rows)[0] == {r.id for r in post_filter(rows, parse_query("re:/^svc-/"))}


def test_match_entity_rows_flags_an_exhausted_budget():
    """A partial match set rendered as 'these are the matches, everything else is dimmed'
    is a false negative presented as fact — the caller has to be able to say so."""
    import app.intel.queries as q

    original = q.REGEX_MATCH_BUDGET_S
    q.REGEX_MATCH_BUDGET_S = 0.0
    try:
        matched, partial = q.match_entity_rows(q.parse_query("re:/x/"), _rows((1, "x"), (2, "x")))
    finally:
        q.REGEX_MATCH_BUDGET_S = original
    assert partial is True
    assert matched == set()


def test_match_entity_rows_truncates_long_values_like_the_dashboard():
    from app.intel.queries import REGEX_INPUT_MAX, match_entity_rows, parse_query

    row = _Row(1, "a" * REGEX_INPUT_MAX + "needle")
    assert match_entity_rows(parse_query("re:/needle/"), [row])[0] == set()


def test_strict_post_filter_drops_what_a_spent_budget_left_unscanned():
    """The dashboard keeps the unscanned remainder of a positive regex (its count is already
    flagged approximate); a rule must never tag a row nobody checked."""
    import app.intel.queries as q
    from app.intel.queries import parse_query, post_filter

    rows = [Entity(id=i, value=f"svc-{i}", entity_type="user") for i in range(5)]
    original = q.REGEX_MATCH_BUDGET_S
    q.REGEX_MATCH_BUDGET_S = 0.0
    try:
        assert [e.id for e in post_filter(rows, parse_query("re:/^svc-/"))] == [0, 1, 2, 3, 4]
        assert post_filter(rows, parse_query("re:/^svc-/"), strict=True) == []
        assert post_filter(rows, parse_query("-re:/^svc-/")) == []
    finally:
        q.REGEX_MATCH_BUDGET_S = original


def test_match_entity_rows_answers_list_terms_for_the_graph():
    from app.intel.queries import match_entity_rows, parse_query

    rows = [
        Entity(id=1, value="CertUtil.exe", entity_type="executable"),
        Entity(id=2, value="custom.exe", entity_type="executable"),
        Entity(id=3, value="evil-c2.tk", entity_type="domain"),
    ]
    lists = {"lolbas": ("exact", ("certutil.exe",)), "suspicious_tlds": ("suffix", (".tk",))}
    assert match_entity_rows(parse_query("list:lolbas"), rows, lists=lists) == ({1}, False)
    assert match_entity_rows(parse_query("list:suspicious_tlds"), rows, lists=lists) == ({3}, False)
    assert match_entity_rows(parse_query("-list:lolbas re:/exe$/"), rows, lists=lists) == ({2}, False)
    # A list the caller did not load matches nothing, the answer the SQL gives too.
    assert match_entity_rows(parse_query("list:nope"), rows, lists=lists) == (set(), False)
