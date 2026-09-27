"""The condition editor's grammar is the parsers', shipped rather than restated.

The editor tokenises in JavaScript, because it is a highlight overlay behind a real
`<textarea>`. A grammar written by hand over there is a grammar that drifts: a prefix added
to `queries._PREFIXES` would simply stop being coloured, which nobody reports. So the
prefixes cross the wire as a Jinja global and these tests hold the two ends together.

They also pin what the client is *not* allowed to decide. In both grammars an unrecognised
`word:value` is a deliberate literal search — filenames and rule ids contain colons — so
nothing that would let the client call a term invalid may appear in the payload.

That the *editor* honours that rule is asserted behaviourally, in
`tests/js/condition-editor.test.mjs` (`sigma:proc_creation` stays plain), which `task
ci:test` runs. There is no source-scanning twin here: counting `lt-cond-bad` occurrences
measures a number that changes for reasons that are not the rule.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.templates_config import templates

FIXTURE = Path("tests/js/condition-grammar.fixture.json")


def _grammar() -> dict:
    return templates.env.globals["condition_grammar"]


class TestItComesFromTheParsers:
    def test_the_entity_prefixes_are_the_entity_parsers(self):
        from app.intel.queries import _PREFIXES

        assert set(_grammar()["entity"]["prefixes"]) == set(_PREFIXES)

    def test_the_job_prefixes_are_the_job_parsers(self):
        from app.jobs_query import PREFIXES

        assert set(_grammar()["job"]["prefixes"]) == set(PREFIXES)

    def test_the_operators_are_the_parsers(self):
        from app.intel.queries import _AND, _OR

        assert _grammar()["operators"] == [_OR, _AND]

    def test_prefixes_are_longest_first(self):
        """`re:/` has to be tried before any shorter prefix could claim its head, and the
        client's `find` takes the first match."""
        for scope in ("entity", "job"):
            lengths = [len(p) for p in _grammar()[scope]["prefixes"]]
            assert lengths == sorted(lengths, reverse=True), f"{scope} prefixes are not longest-first"

    def test_each_scope_names_the_endpoint_that_completes_it(self):
        assert _grammar()["entity"]["suggest_url"] == "/intel/search-suggest"
        assert _grammar()["job"]["suggest_url"] == "/jobs/search-suggest"


class TestItCarriesNoAuthorityOverValidity:
    def test_it_ships_structure_only(self):
        """No value sets, no flags, no severities — nothing the client could use to paint a
        working term red. Validity is the 400 ms server preview's job; it is the only thing
        that actually parses."""
        for scope in ("entity", "job"):
            assert set(_grammar()[scope]) == {"prefixes", "suggest_url"}
        assert set(_grammar()) == {"entity", "job", "operators", "regex_prefix"}


class TestTheJsFixtureTracksIt:
    def test_the_js_fixture_matches_the_shipped_grammar(self):
        """`tests/js/condition-editor.test.mjs` reads this file. Regenerate it with:

            pdm run -- python -c "import json; from app.templates_config import templates; \\
              open('tests/js/condition-grammar.fixture.json','w').write( \\
              json.dumps(templates.env.globals['condition_grammar'], indent=2, sort_keys=True) + '\\n')"
        """
        assert FIXTURE.exists(), f"{FIXTURE} is missing; the JS tests cannot run"
        assert json.loads(FIXTURE.read_text()) == _grammar(), "the JS fixture has drifted from condition_grammar — regenerate it (see this test's docstring)"
