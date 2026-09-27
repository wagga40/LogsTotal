"""Tier-1: the conjunctive query grammar.

A parser that returns exactly one `kind` cannot express "a LOLBin that is also tagged
apt28" — quick-filter chips would have to *overwrite* the search box, which means one
filter at a time and a typed query silently destroyed.

Two properties matter most here and are easy to break:

1. **Phrase-mode back-compat.** Whitespace only means AND once a query opts into the
   structured syntax. A plain multi-word query stays one literal term, so a saved phrase
   search keeps matching the same entities.
2. **`parse_search_query` is a thin wrapper.** It sits over the same
   `_parse_term`, so the two entry points cannot drift on what a single term means.
"""

from __future__ import annotations

import pytest

from app.intel.queries import (
    ATTR_FILTERS,
    MAX_REGEX_TERMS,
    MAX_TERMS,
    parse_query,
    parse_search_query,
    tokenize_query,
)


def kinds(q):
    return [t["kind"] for t in q["terms"]]


class TestTokenizer:
    def test_splits_on_whitespace(self):
        assert tokenize_query("label:lolbin tag:apt28") == ["label:lolbin", "tag:apt28"]

    def test_regex_with_spaces_survives_as_one_token(self):
        # Splitting this on whitespace would turn one valid pattern into two junk terms.
        assert tokenize_query("re:/^svc a.*/ tag:x") == ["re:/^svc a.*/", "tag:x"]

    def test_escaped_slash_does_not_end_a_regex(self):
        assert tokenize_query(r"re:/a\/b/ x") == [r"re:/a\/b/", "x"]

    def test_quoted_run_is_one_token_without_its_quotes(self):
        assert tokenize_query('"powershell -enc" tag:x') == ["powershell -enc", "tag:x"]

    def test_unterminated_quote_takes_the_rest(self):
        assert tokenize_query('"abc def') == ["abc def"]

    def test_negated_regex_is_one_token(self):
        assert tokenize_query("-re:/^a b/ y") == ["-re:/^a b/", "y"]


class TestPhraseModeBackCompat:
    """A query with no structured syntax stays exactly one literal term."""

    @pytest.mark.parametrize(
        "raw",
        ["powershell -enc payload", "some multi word value", "C:\\Windows\\System32", "10.0.0.1"],
    )
    def test_unstructured_query_is_a_single_literal_of_the_whole_string(self, raw):
        q = parse_query(raw)
        assert kinds(q) == ["literal"]
        assert q["terms"][0]["value"] == raw

    def test_a_leading_dash_word_alone_does_not_trigger_structure(self):
        """`-enc` is part of a phrase, not a negation — this is the back-compat case."""
        q = parse_query("powershell -enc")
        assert kinds(q) == ["literal"]
        assert q["terms"][0]["value"] == "powershell -enc"

    def test_negating_a_plain_literal_is_spelled_with_quotes(self):
        """Quotes are how you opt a bare word into being a negatable term."""
        q = parse_query('tag:x -"enc"')
        assert kinds(q) == ["tag", "literal"]
        assert q["terms"][1]["negated"] is True
        assert q["terms"][1]["value"] == "enc"

    def test_wildcards_still_work_unstructured(self):
        q = parse_query("admin*")
        assert kinds(q) == ["wildcard"]


class TestConjunction:
    def test_two_labels_and_together(self):
        q = parse_query("label:lolbin tag:apt28")
        assert kinds(q) == ["attr", "tag"]

    def test_label_falls_back_to_tag_for_an_unknown_key(self):
        q = parse_query("label:apt28 label:lolbin")
        assert kinds(q) == ["tag", "attr"]

    def test_system_label_wins_a_collision_with_a_user_tag(self):
        # Someone may well have tagged an entity "lolbin"; `tag:lolbin` still reaches it.
        assert parse_query("label:lolbin")["terms"][0]["kind"] == "attr"
        assert parse_query("tag:lolbin")["terms"][0]["kind"] == "tag"

    def test_label_honours_attr_aliases(self):
        assert parse_query("label:suspicious")["terms"][0]["attr_key"] == "suspicious_tld"

    def test_quoted_literal_keeps_its_spaces(self):
        q = parse_query('"multi word" tag:x')
        assert q["terms"][0]["value"] == "multi word"

    def test_negation_is_flagged_on_the_term(self):
        q = parse_query("-tag:noisy label:dga")
        assert q["terms"][0]["negated"] is True
        assert q["terms"][1]["negated"] is False

    def test_mixed_kinds_all_parse(self):
        q = parse_query("label:lolbin cidr:10.0.0.0/8 admin* tag:x")
        assert kinds(q) == ["attr", "cidr", "wildcard", "tag"]


class TestCaps:
    def test_terms_are_capped_and_reported(self):
        q = parse_query(" ".join(f"tag:t{i}" for i in range(MAX_TERMS + 5)))
        assert len(q["terms"]) == MAX_TERMS
        assert any("terms were applied" in e for e in q["errors"])

    def test_regex_terms_are_capped_harder(self):
        q = parse_query(" ".join([r"re:/a/"] * (MAX_REGEX_TERMS + 2)))
        assert sum(1 for k in kinds(q) if k == "regex") == MAX_REGEX_TERMS
        assert any("regex terms" in e for e in q["errors"])

    def test_errors_surface_from_a_bad_term(self):
        q = parse_query("attr:nosuchkey tag:x")
        assert any("unknown attr" in e for e in q["errors"])


class TestSingleTermEntryPointIsUnchanged:
    """`parse_search_query` must keep behaving exactly as it always did."""

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "plain",
            "admin*",
            "tag:apt28,ransomware",
            "attr:lolbin",
            "cidr:10.0.0.0/8",
            "re:/^admin/",
            "attr:bogus",
            "cidr:not-a-network",
            "powershell -enc payload",
        ],
    )
    def test_matches_the_first_term_of_parse_query(self, raw):
        single = parse_search_query(raw)
        first = parse_query(raw)["terms"]
        if not first:
            assert single["kind"] == "literal" and not single.get("value")
            return
        assert single["kind"] == first[0]["kind"]
        assert single.get("value") == first[0].get("value")
        assert single.get("error") == first[0].get("error")

    def test_every_attr_key_is_reachable_through_label(self):
        for key in ATTR_FILTERS:
            assert parse_query(f"label:{key}")["terms"][0]["kind"] == "attr", key
