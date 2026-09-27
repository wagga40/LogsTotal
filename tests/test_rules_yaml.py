"""Rules as data: the one YAML document the seed files, the export and the import share.

Tier 1 for the pure half — the document, the validator, the column mapping, the shipped
files — and `async_db` for the two writers. Two properties matter most. Every shipped default
is a real expression the grammar compiles, so "the logic is in the rule" is checked against
the file, not asserted in a docstring. And the seeding policy — the file updates what nobody
edited — is exercised against a temporary copy of the files, because both obvious policies
(overwrite on boot, never overwrite) fail in ways that only show after an upgrade.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import select

import app.models  # noqa: F401 — populate Base.metadata
from app.intel.queries import list_terms, parse_query
from app.intel.rule_lists import ListSpec, list_hash, load_lists, write_list
from app.intel.rules_yaml import (
    MAX_RULES_PER_DOCUMENT,
    RuleSpec,
    apply_spec,
    dump_rules_yaml,
    import_rules,
    load_rules_dir,
    parse_rules_yaml,
    rules_dir,
    spec_from_rule,
    spec_hash,
    sync_rules_from_dir,
    validate_spec,
)
from app.json_utils import dumps as json_dumps
from app.models import IntelRule, RuleList, RuleListValue

SPEC = RuleSpec(
    key="demo",
    name="Demo",
    description="A demonstration.",
    scope="entity",
    entity_types=("executable",),
    criteria="list:lolbas -tag:known-good",
    tags=(("demo", "orange"),),
    notify=False,
    enabled=True,
)

JOB_SPEC = RuleSpec(
    name="Serious and unreviewed",
    scope="job",
    criteria="sev:critical -tag:reviewed",
    tags=(("hot", "red"),),
    notify=True,
    webhook_url="https://hooks.example/x",
    webhook_method="PUT",
    webhook_headers_json=json_dumps({"X-Auth": "t"}),
    webhook_enabled=True,
)

LISTS = [
    ListSpec(name="lolbas", match="exact", description="Two LOLBins.", values=("certutil.exe", "mshta.exe")),
    ListSpec(name="suspicious_tlds", match="suffix", values=(".tk",)),
]
KNOWN = {lspec.name for lspec in LISTS}


# ── the document ─────────────────────────────────────────────────────────────


def test_dump_then_parse_is_the_identity():
    doc = parse_rules_yaml(dump_rules_yaml([SPEC, JOB_SPEC], lists=LISTS))
    assert doc.errors == []
    assert doc.rules == [SPEC, JOB_SPEC]
    assert doc.lists == LISTS


def test_the_dump_is_in_reading_order_and_never_folds_a_long_criteria():
    text = dump_rules_yaml([SPEC], lists=LISTS)
    assert text.index("lists:") < text.index("rules:")
    assert text.index("key:") < text.index("name: Demo") < text.index("criteria:") < text.index("tags:")
    long = replace(SPEC, criteria="-cidr:" + ",".join(f"10.{i}.0.0/16" for i in range(16)))
    assert long.criteria in dump_rules_yaml([long])


def test_keys_can_be_left_out_of_an_export():
    assert "key:" not in dump_rules_yaml([SPEC], with_keys=False)
    assert "key: demo" in dump_rules_yaml([SPEC])


def test_the_secret_is_not_part_of_the_format():
    rule = IntelRule(name="x", builtin_key=None, webhook_secret_encrypted="enc", notify_job_watch=True, seed_hash="abc")
    apply_spec(rule, JOB_SPEC)
    text = dump_rules_yaml([spec_from_rule(rule)])
    assert "enc" not in text and "secret" not in text and "notify_job_watch" not in text and "seed_hash" not in text
    assert rule.webhook_secret_encrypted == "enc" and rule.notify_job_watch is True and rule.seed_hash == "abc"


def test_condition_is_accepted_as_a_spelling_of_criteria():
    """The page says *condition*; the column and the file say *criteria*. A file written from
    the page's vocabulary loads too."""
    doc = parse_rules_yaml("rules:\n  - name: x\n    condition: 'tag:a'\n")
    assert doc.errors == [] and doc.rules[0].criteria == "tag:a"


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("rules: [", "not valid YAML"),
        ("", "rules:"),
        ("name: x", "rules:"),
        ("rules: 3", "`rules:` must be a list"),
        ("lists: 3", "`lists:` must be a list"),
        ("rules:\n  - 3\n", "rules[0]: expected a mapping"),
        ("lists:\n  - 3\n", "lists[0]: expected a mapping"),
        ("lists:\n  - name: Bad Name\n    values: [a]\n", "lists[0] (bad name): name must be"),
        ("lists:\n  - name: empty\n", "at least one value"),
        ("lists:\n  - name: a\n    match: regex\n    values: [x]\n", "match must be one of"),
        ("lists:\n  - name: a\n    values: [x]\n  - name: a\n    values: [y]\n", "duplicate list name"),
        ("rules:\n  - name: x\n    criteria: 'attr:nope'\n", "rules[0] (x): unknown attr"),
        ("rules:\n  - key: a\n    name: x\n  - key: a\n    name: y\n", "duplicate key"),
        ("rules:\n  - name: same\n  - name: Same\n", "duplicate name"),
        ("rules:\n  - name: x\n    tags: 3\n", "tags must be a list"),
        ("rules:\n  - name: x\n    enabled: yes please\n", "enabled must be true or false"),
        ("rules:\n  - name: x\n    webhook: {url: 'https://h.example/x', headers: [1]}\n", "webhook.headers must be a mapping"),
        ("rules:\n" + "".join(f"  - name: r{i}\n" for i in range(MAX_RULES_PER_DOCUMENT + 1)), "at most"),
        ("rules:\n  - name: x\n    description: '" + "d" * (600 * 1024) + "'\n", "larger than"),
    ],
)
def test_a_bad_document_names_its_problem_and_never_raises(text, fragment):
    doc = parse_rules_yaml(text)
    assert doc.errors and any(fragment in e for e in doc.errors), doc.errors


def test_a_good_entry_survives_a_bad_neighbour_in_the_parse():
    """The parse returns what it could read; all-or-nothing is the *import's* stance."""
    doc = parse_rules_yaml("rules:\n  - name: ok\n    criteria: 'tag:a'\n  - name: bad\n    criteria: 're:/^a/ OR tag:x'\n")
    assert [s.name for s in doc.rules] == ["ok"]
    assert len(doc.errors) == 1 and doc.errors[0].startswith("rules[1] (bad):")


def test_tags_accept_a_bare_name_and_a_name_with_a_colour():
    doc = parse_rules_yaml("rules:\n  - name: x\n    tags: [plain, {name: APT29, color: red}, {name: dup, color: nope}]\n")
    assert doc.errors == []
    assert doc.rules[0].tags == (("plain", "gray"), ("apt29", "red"), ("dup", "gray"))


def test_list_values_accept_a_list_or_text_one_per_line():
    doc = parse_rules_yaml("lists:\n  - name: a\n    values: [X, x, ' y ']\n  - name: b\n    values: |\n      one\n      Two, three\n")
    assert doc.errors == []
    assert doc.lists[0].values == ("x", "y") and doc.lists[1].values == ("one", "two", "three")


# ── the validator ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "change, fragment",
    [
        ({"name": ""}, "Rule needs a name"),
        ({"name": "x" * 121}, "120"),
        ({"description": "d" * 501}, "500"),
        ({"key": "Bad Key"}, "key must be"),
        ({"scope": "case"}, "scope must be one of"),
        ({"entity_types": ("widget",)}, "unknown entity type"),
        ({"criteria": "x" * 501}, "500"),
        ({"criteria": "job:4 tag:x"}, "job: cannot be used"),
        ({"criteria": "re:/^a/ OR tag:x"}, "cannot be combined with OR"),
        ({"criteria": "list:lolbas,gtfobins"}, "one per term"),
        ({"criteria": "attr:bogus"}, "unknown attr"),
        ({"webhook_url": "ftp://x"}, "Webhook URL rejected"),
        ({"webhook_url": "https://169.254.169.254/"}, "Webhook URL rejected"),
        ({"webhook_method": "GET"}, "Method must be one of"),
        ({"webhook_headers_json": json_dumps({"Host": "evil"})}, "cannot be overridden"),
        ({"webhook_headers_json": "not json"}, "JSON object"),
    ],
)
def test_validate_spec_names_the_problem(change, fragment):
    errors = validate_spec(replace(SPEC, **change))
    assert errors and fragment in errors[0], errors


def test_a_list_the_database_lacks_is_an_error_only_when_the_caller_can_ask():
    """The parser is pure, so `list:nope` parses; whoever holds a session passes the names."""
    assert validate_spec(replace(SPEC, criteria="list:nope")) == []
    assert validate_spec(replace(SPEC, criteria="list:nope"), known_lists=KNOWN) == ["unknown list: nope — try lolbas, suspicious_tlds"]
    assert validate_spec(replace(SPEC, criteria="list:nope"), known_lists=set()) == ["unknown list: nope — no lists are defined yet"]
    assert validate_spec(SPEC, known_lists=KNOWN) == []


def test_a_job_rule_is_validated_by_the_jobs_grammar():
    assert validate_spec(JOB_SPEC) == []
    assert validate_spec(replace(JOB_SPEC, criteria="sev:notalevel"))


# ── the column mapping and the hash ──────────────────────────────────────────


def test_apply_then_read_back_is_the_identity():
    rule = IntelRule(builtin_key="demo")
    apply_spec(rule, SPEC)
    assert spec_from_rule(rule) == SPEC
    assert rule.entity_types == '["executable"]' and rule.action_tag == "demo" and rule.action_tag_color == "orange"


def test_a_job_rule_stores_no_entity_types_and_a_webhook_needs_a_url_to_be_enabled():
    rule = IntelRule()
    apply_spec(rule, replace(JOB_SPEC, entity_types=("executable",)))
    assert rule.entity_types == "[]"
    apply_spec(rule, replace(JOB_SPEC, webhook_url=None, webhook_enabled=True))
    assert rule.webhook_enabled is False


def test_the_hash_ignores_enabled_and_key_and_nothing_else():
    assert spec_hash(SPEC) == spec_hash(replace(SPEC, enabled=False)) == spec_hash(replace(SPEC, key=None))
    assert spec_hash(SPEC) != spec_hash(replace(SPEC, criteria="list:gtfobins"))
    assert spec_hash(SPEC) != spec_hash(replace(SPEC, tags=(("demo", "red"),)))
    assert spec_hash(SPEC) != spec_hash(replace(SPEC, description="other"))
    # A row round-trips to the hash it was seeded with — the property the seeder relies on.
    rule = IntelRule(builtin_key="demo")
    apply_spec(rule, SPEC)
    assert spec_hash(spec_from_rule(rule)) == spec_hash(SPEC)
    assert list_hash(LISTS[0]) != list_hash(replace(LISTS[0], values=("certutil.exe",)))


# ── the shipped files ────────────────────────────────────────────────────────


class TestTheShippedFiles:
    def test_they_parse_clean_with_unique_keys_and_named_lists(self):
        doc = load_rules_dir(rules_dir())
        assert doc.errors == []
        keys = [s.key for s in doc.rules]
        assert len(keys) == 36 and len(set(keys)) == 36 and all(keys)
        assert [lspec.name for lspec in doc.lists] == [
            "lolbas",
            "gtfobins",
            "suspicious_tlds",
            "offensive_tools",
            "remote_access_tools",
            "staging_tools",
            "default_accounts",
            "dynamic_dns",
            "sharing_sites",
        ]

    def test_every_condition_is_a_real_expression(self):
        """The reason the file exists: nothing ships that points at logic living in code. The
        entropy-based DGA heuristic stays an `attr:` a reader can search or build on, not a
        shipped rule nobody can edit."""
        doc = load_rules_dir(rules_dir())
        attr_only = sorted(s.key for s in doc.rules if "attr:" in s.criteria)
        assert attr_only == [], f"hiding behind attr: {attr_only}"
        known = {lspec.name for lspec in doc.lists}
        for spec in doc.rules:
            assert validate_spec(spec, known_lists=known) == [], spec.key
            assert len(spec.criteria) <= 500

    def test_every_list_a_rule_tests_is_shipped_beside_it(self):
        doc = load_rules_dir(rules_dir())
        named = {name for s in doc.rules if s.scope == "entity" for name in list_terms(parse_query(s.criteria))}
        assert named == {lspec.name for lspec in doc.lists}, "every list is tested by a rule, and every tested list ships"

    def test_the_lists_are_what_the_detection_pipeline_started_from(self):
        """The rules' own copies, seeded from what the threat config carried when they were
        split off. They may drift by choice afterwards; this pins the starting point."""
        by_name = {lspec.name: lspec for lspec in load_rules_dir(rules_dir()).lists}
        assert len(by_name["lolbas"].values) == 72 and "certutil.exe" in by_name["lolbas"].values
        assert len(by_name["gtfobins"].values) == 92 and "nmap" in by_name["gtfobins"].values
        assert by_name["suspicious_tlds"].match == "suffix" and by_name["suspicious_tlds"].values == (".tk", ".top", ".pw", ".bit", ".onion")
        assert all(lspec.description for lspec in by_name.values())

    def test_every_rule_silently_tags_its_own_key(self):
        """Load-bearing rather than defaults: `_rule_may_run_on`'s private-job exemption and
        the alert-ledger skip are both conditional on a shared rule neither alerting nor
        delivering. Only `lookalike` ships switched off — its exclusions need tuning."""
        doc = load_rules_dir(rules_dir())
        for spec in doc.rules:
            assert spec.scope in ("entity", "job"), spec.key
            if spec.scope == "entity":
                assert spec.entity_types, f"{spec.key} applies to every type"
            assert spec.tags and spec.tags[0][0] == spec.key, spec.key
            assert spec.notify is False and spec.webhook_url is None, spec.key
            assert spec.enabled is (spec.key != "lookalike"), spec.key
            assert spec.description, f"{spec.key} explains nothing"
        assert [s.key for s in doc.rules if s.scope == "job"] == ["needs_triage", "rerun", "clean"]

    def test_a_directory_load_reports_a_keyless_rule_and_a_missing_directory(self, tmp_path):
        (tmp_path / "a.yml").write_text("rules:\n  - name: keyless\n", encoding="utf-8")
        doc = load_rules_dir(tmp_path)
        assert doc.rules == [] and doc.errors and "no key" in doc.errors[0]
        assert load_rules_dir(tmp_path / "missing").errors[0].startswith("no rules directory")

    def test_the_shipped_directory_is_the_project_root_one(self):
        assert rules_dir() == Path(__file__).resolve().parents[1] / "rules"
        assert (rules_dir() / "builtin.yml").exists() and (rules_dir() / "lists.yml").exists()


# ── the seeder: the file updates what nobody edited ──────────────────────────


def _write_dir(tmp_path: Path, rules: list[RuleSpec], lists: list[ListSpec]) -> Path:
    d = tmp_path / "rules"
    d.mkdir(exist_ok=True)
    (d / "lists.yml").write_text(dump_rules_yaml([], lists=lists), encoding="utf-8")
    (d / "builtin.yml").write_text(dump_rules_yaml(rules), encoding="utf-8")
    return d


SEED_RULES = [
    replace(SPEC, key="lolbin", name="LOLBin", tags=(("lolbin", "orange"),)),
    replace(SPEC, key="tld", name="Suspicious TLD", entity_types=("domain",), criteria="list:suspicious_tlds", tags=(("tld", "yellow"),)),
]


@pytest.mark.anyio
class TestSeeding:
    async def _rule(self, db, key):
        return (await db.execute(select(IntelRule).where(IntelRule.builtin_key == key))).scalar_one()

    async def test_the_shipped_directory_seeds_lists_then_rules_and_is_idempotent(self, async_db):
        first = await sync_rules_from_dir(async_db, rules_dir())
        await async_db.commit()
        assert (first.created, first.updated, first.kept, first.errors) == (36, 0, 0, [])
        assert (first.lists_created, first.lists_updated, first.lists_kept) == (9, 0, 0)
        rows = {r.builtin_key: r for r in (await async_db.execute(select(IntelRule).where(IntelRule.is_builtin.is_(True)))).scalars().all()}
        assert rows["lolbin"].query == "list:lolbas" and rows["lolbin"].seed_hash and rows["lolbin"].owner_user_id is None
        values = (await async_db.execute(select(RuleListValue.value).join(RuleList).where(RuleList.name == "lolbas"))).scalars().all()
        assert len(values) == 72 and "certutil.exe" in values

        second = await sync_rules_from_dir(async_db, rules_dir())
        await async_db.commit()
        assert (second.created, second.updated, second.kept) == (0, 0, 36)
        assert (second.lists_created, second.lists_updated, second.lists_kept) == (0, 0, 9)
        assert "36 kept" in second.summary() and "9 kept" in second.summary() and "retired" not in second.summary()

    async def test_the_file_updates_a_rule_nobody_edited(self, async_db, tmp_path):
        d = _write_dir(tmp_path, SEED_RULES, LISTS)
        await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        before = (await self._rule(async_db, "lolbin")).seed_hash

        _write_dir(tmp_path, [replace(SEED_RULES[0], criteria="list:lolbas", description="tightened"), *SEED_RULES[1:]], LISTS)
        result = await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        assert (result.created, result.updated, result.kept) == (0, 1, 1)
        rule = await self._rule(async_db, "lolbin")
        assert rule.query == "list:lolbas" and rule.description == "tightened" and rule.seed_hash != before

    async def test_an_admins_edit_is_kept_and_switching_off_is_not_an_edit(self, async_db, tmp_path):
        d = _write_dir(tmp_path, SEED_RULES, LISTS)
        await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        edited = await self._rule(async_db, "lolbin")
        edited.query = "list:lolbas -tag:known-good -tag:reviewed"  # an admin's edit
        switched_off = await self._rule(async_db, "tld")
        switched_off.enabled = False  # not an edit
        await async_db.commit()

        _write_dir(tmp_path, [replace(s, description="v2") for s in SEED_RULES], LISTS)
        result = await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        assert (result.updated, result.kept) == (1, 1)
        await async_db.refresh(edited)
        await async_db.refresh(switched_off)
        assert edited.query == "list:lolbas -tag:known-good -tag:reviewed" and edited.description != "v2"
        assert switched_off.description == "v2" and switched_off.enabled is False

    async def test_a_row_from_the_first_cut_is_treated_as_unedited(self, async_db, tmp_path):
        """Rows seeded before `seed_hash` existed carry the old seed's exact shape —
        `attr:<key>` and its fixed description — and nothing an operator wrote, so the file
        replaces them."""
        async_db.add(
            IntelRule(
                name="Living-off-the-land binary",
                description="Built-in label. Applies the tag 'lolbin' to every entity matching attr:lolbin.",
                owner_user_id=None,
                is_builtin=True,
                builtin_key="lolbin",
                scope="entity",
                query="attr:lolbin",
                entity_types='["executable"]',
                action_tag="lolbin",
                action_tag_color="orange",
                action_notify=False,
                enabled=False,
            )
        )
        await async_db.commit()
        d = _write_dir(tmp_path, SEED_RULES, LISTS)
        result = await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        assert (result.created, result.updated) == (1, 1)
        rule = await self._rule(async_db, "lolbin")
        assert rule.query == SEED_RULES[0].criteria and rule.seed_hash and rule.enabled is False

    async def test_a_row_identical_to_the_file_is_adopted_even_without_a_hash(self, async_db, tmp_path):
        """An admin reset or imported it to exactly what ships: mark it, so the next
        release's change reaches it. Updating it would change nothing anyway."""
        d = _write_dir(tmp_path, SEED_RULES, LISTS)
        rule = IntelRule(name="", owner_user_id=None, is_builtin=True, builtin_key="lolbin", seed_hash=None)
        apply_spec(rule, SEED_RULES[0])
        async_db.add(rule)
        await write_list(async_db, None, LISTS[0], seed_hash=None)
        await async_db.commit()

        result = await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        assert (result.created, result.updated, result.kept) == (1, 0, 1)
        assert (result.lists_created, result.lists_updated, result.lists_kept) == (1, 0, 1)
        await async_db.refresh(rule)
        assert rule.seed_hash == spec_hash(SEED_RULES[0])
        row = (await async_db.execute(select(RuleList).where(RuleList.name == "lolbas"))).scalar_one()
        assert row.seed_hash == list_hash(LISTS[0])

        # …and from then on the file updates it like any other unedited row.
        _write_dir(tmp_path, [replace(SEED_RULES[0], description="v2"), SEED_RULES[1]], LISTS)
        result = await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        await async_db.refresh(rule)
        assert result.updated == 1 and rule.description == "v2"

    async def test_an_edited_list_is_kept_and_an_unedited_one_updated(self, async_db, tmp_path):
        d = _write_dir(tmp_path, SEED_RULES, LISTS)
        await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        rows = {row.name: row for row, _spec in await load_lists(async_db)}
        await write_list(async_db, rows["lolbas"], replace(LISTS[0], values=("certutil.exe",)), seed_hash=None)  # an admin's edit
        await async_db.commit()

        _write_dir(tmp_path, SEED_RULES, [replace(LISTS[0], values=("certutil.exe", "mshta.exe", "rundll32.exe")), replace(LISTS[1], values=(".tk", ".top"))])
        result = await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        assert (result.lists_updated, result.lists_kept) == (1, 1)
        by_name = {spec.name: spec for _row, spec in await load_lists(async_db)}
        assert by_name["lolbas"].values == ("certutil.exe",)
        assert by_name["suspicious_tlds"].values == (".tk", ".top")

    async def test_what_the_file_drops_is_retired_unless_somebody_edited_it(self, async_db, tmp_path):
        """A retired shipped rule should not linger on every instance until an admin notices.
        Its tags stay — they are facts about what matched. A list goes the same way, and only
        when no rule still names it."""
        d = _write_dir(tmp_path, SEED_RULES, LISTS)
        await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        edited = await self._rule(async_db, "tld")
        edited.query = "list:suspicious_tlds -tag:known-good"  # an admin's edit
        await async_db.commit()

        _write_dir(tmp_path, [], [])
        result = await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        assert (result.retired, result.kept) == (1, 1)
        assert (result.lists_retired, result.lists_kept) == (1, 1), "lolbas nothing names goes; suspicious_tlds the edited rule names stays"
        assert "1 retired" in result.summary()
        keys = (await async_db.execute(select(IntelRule.builtin_key))).scalars().all()
        assert keys == ["tld"]
        assert [spec.name for _row, spec in await load_lists(async_db)] == ["suspicious_tlds"]

    async def test_a_first_cut_row_the_file_no_longer_ships_is_retired_too(self, async_db, tmp_path):
        """The `dga` case: seeded by the first cut as `attr:dga`, never edited, and no longer
        shipped — nothing a reader could edit, so nothing to keep."""
        async_db.add(
            IntelRule(
                name="Looks algorithmically generated",
                description="Built-in label. Applies the tag 'dga' to every entity matching attr:dga.",
                owner_user_id=None,
                is_builtin=True,
                builtin_key="dga",
                scope="entity",
                query="attr:dga",
                entity_types='["domain"]',
                action_tag="dga",
                action_tag_color="red",
                action_notify=False,
            )
        )
        await async_db.commit()
        result = await sync_rules_from_dir(async_db, _write_dir(tmp_path, SEED_RULES, LISTS))
        await async_db.commit()
        assert result.retired == 1
        assert (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "dga"))).scalar_one_or_none() is None

    async def test_an_imported_shared_rule_is_not_mistaken_for_a_first_cut_row(self, async_db, tmp_path):
        """An admin brings `dga` back by importing `key: dga`, `criteria: attr:dga`. The NULL
        hash plus that condition read as the first cut's own row, so it was retired on the
        next start — every start. The first cut also wrote a fixed description; an import
        does not."""
        async_db.add(
            IntelRule(
                name="DGA",
                description="Brought back by hand.",
                owner_user_id=None,
                is_builtin=True,
                builtin_key="dga",
                scope="entity",
                query="attr:dga",
                entity_types="[]",
                action_tag="dga",
                seed_hash=None,
            )
        )
        await async_db.commit()

        result = await sync_rules_from_dir(async_db, _write_dir(tmp_path, SEED_RULES, LISTS))
        await async_db.commit()
        assert result.retired == 0
        assert (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "dga"))).scalar_one_or_none() is not None

    async def test_a_rules_file_that_does_not_parse_retires_nothing(self, async_db, tmp_path):
        """A truncated overlay or a bad hand edit made every shipped key look dropped, and the
        seeder deleted every unedited shared rule — labelling stopped on every new job, and
        re-creating them later reset each "switched off" back to on."""
        d = _write_dir(tmp_path, SEED_RULES, LISTS)
        await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        (d / "builtin.yml").write_text((d / "builtin.yml").read_text() + "\n  - key: [unterminated\n", encoding="utf-8")

        result = await sync_rules_from_dir(async_db, d)
        await async_db.commit()
        assert result.errors
        assert (result.retired, result.lists_retired) == (0, 0)
        assert len((await async_db.execute(select(IntelRule))).scalars().all()) == len(SEED_RULES)

    async def test_a_missing_rules_directory_retires_nothing(self, async_db, tmp_path):
        await sync_rules_from_dir(async_db, _write_dir(tmp_path, SEED_RULES, LISTS))
        await async_db.commit()

        result = await sync_rules_from_dir(async_db, tmp_path / "not-there")
        await async_db.commit()
        assert result.retired == 0
        assert len((await async_db.execute(select(IntelRule))).scalars().all()) == len(SEED_RULES)

    async def test_a_rule_naming_a_list_nothing_defines_is_reported_not_seeded(self, async_db, tmp_path):
        d = _write_dir(tmp_path, [replace(SPEC, key="orphan", criteria="list:nope")], [])
        result = await sync_rules_from_dir(async_db, d)
        assert result.created == 0 and any("unknown list: nope" in e for e in result.errors)


# ── the import ───────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestImport:
    async def _rows(self, db):
        return (await db.execute(select(IntelRule))).scalars().all()

    async def _lolbas(self, db):
        await write_list(db, None, LISTS[0], seed_hash=None)
        await db.commit()

    async def test_a_member_creates_then_updates_by_name(self, async_db, member_user):
        await self._lolbas(async_db)
        result = await import_rules(async_db, [SPEC], user=member_user, as_shared=False, can_write_lists=False)
        await async_db.commit()
        assert (result.created, result.updated, result.errors) == (1, 0, [])
        assert result.summary() == "1 rule created, 0 updated"
        row = (await async_db.execute(select(IntelRule).where(IntelRule.owner_user_id == member_user.id))).scalar_one()
        assert row.query == SPEC.criteria and row.is_builtin is False and row.builtin_key is None and row.seed_hash is None

        again = await import_rules(async_db, [replace(SPEC, criteria="tag:known-good")], user=member_user, as_shared=False, can_write_lists=False)
        await async_db.commit()
        assert (again.created, again.updated) == (0, 1)
        await async_db.refresh(row)
        assert row.query == "tag:known-good"
        assert len(await self._rows(async_db)) == 1

    async def test_it_is_all_or_nothing(self, async_db, member_user):
        await self._lolbas(async_db)
        bad = replace(SPEC, key="broken", name="Broken", criteria="re:/^a/ OR tag:x")
        result = await import_rules(async_db, [SPEC, bad], user=member_user, as_shared=False, can_write_lists=False)
        await async_db.commit()
        assert result.created == 0 and result.errors and result.errors[0].startswith("rules[1] (broken):")
        assert await self._rows(async_db) == []

    async def test_a_rule_naming_a_list_the_instance_lacks_is_refused(self, async_db, member_user):
        result = await import_rules(async_db, [SPEC], user=member_user, as_shared=False, can_write_lists=False)
        assert result.created == 0 and any("unknown list: lolbas" in e for e in result.errors)

    async def test_a_list_in_the_same_document_satisfies_its_rules(self, async_db, admin_user):
        result = await import_rules(async_db, [SPEC], LISTS, user=admin_user, as_shared=True, can_write_lists=True)
        await async_db.commit()
        assert (result.created, result.lists_created, result.errors) == (1, 2, [])
        assert result.summary() == "1 rule created, 0 updated; 2 lists created, 0 updated"
        row = (await async_db.execute(select(RuleList).where(RuleList.name == "lolbas"))).scalar_one()
        assert row.seed_hash is None, "an imported list is an edit — the seeder must leave it alone"

    async def test_a_member_cannot_import_lists(self, async_db, member_user):
        result = await import_rules(async_db, [], LISTS, user=member_user, as_shared=False, can_write_lists=False)
        assert result.errors and "only an administrator" in result.errors[0]
        assert await load_lists(async_db) == []

    async def test_creations_count_against_the_rule_budget(self, async_db, member_user):
        await self._lolbas(async_db)
        result = await import_rules(async_db, [SPEC, replace(SPEC, key="two", name="Two")], user=member_user, as_shared=False, can_write_lists=False, max_per_user=1)
        assert result.created == 0 and any("limit" in e for e in result.errors)
        assert await self._rows(async_db) == []

    async def test_as_shared_keys_are_the_identity_and_the_row_is_ownerless_and_hands_off(self, async_db, admin_user):
        await self._lolbas(async_db)
        result = await import_rules(async_db, [SPEC], user=admin_user, as_shared=True, can_write_lists=True)
        await async_db.commit()
        assert (result.created, result.updated) == (1, 0)
        row = (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "demo"))).scalar_one()
        assert row.is_builtin is True and row.owner_user_id is None and row.seed_hash is None

        again = await import_rules(async_db, [replace(SPEC, name="Renamed")], user=admin_user, as_shared=True, can_write_lists=True)
        await async_db.commit()
        assert (again.created, again.updated) == (0, 1)
        await async_db.refresh(row)
        assert row.name == "Renamed"

    async def test_a_keyless_rule_in_a_shared_import_comes_back_as_the_importers_own(self, async_db, admin_user):
        """An admin's Download YAML holds the shared rules (keyed) and their own (keyless),
        and promises both re-import. Importing it as shared refused the whole document for
        the keyless half, and importing it as personal duplicated every shared rule. Keyed
        rules go in as shared, keyless ones by name as the admin's own — and the summary
        says so."""
        await self._lolbas(async_db)
        mine = replace(SPEC, key=None, name="My rule")
        result = await import_rules(async_db, [SPEC, mine], user=admin_user, as_shared=True, can_write_lists=True)
        await async_db.commit()
        assert result.errors == []
        assert (await async_db.execute(select(IntelRule).where(IntelRule.builtin_key == "demo"))).scalar_one().is_builtin is True
        own = (await async_db.execute(select(IntelRule).where(IntelRule.name == "My rule"))).scalar_one()
        assert own.owner_user_id == admin_user.id and own.is_builtin is False
        assert "your own" in result.summary()

        again = await import_rules(async_db, [SPEC, mine], user=admin_user, as_shared=True, can_write_lists=True)
        await async_db.commit()
        assert (again.created, again.errors) == (0, [])
        assert len(await self._rows(async_db)) == 2, "a second round trip changes nothing"

    async def test_a_budget_refusal_writes_no_lists(self, async_db, admin_user):
        """ "All or nothing" — but the lists were flushed before the budget was checked, so the
        refusal re-rendered a Lists tab showing lists that were never saved."""
        result = await import_rules(
            async_db,
            [replace(SPEC, key=None, criteria="evil"), replace(SPEC, key=None, name="Two", criteria="evil")],
            [replace(LISTS[0], name="brand_new")],
            user=admin_user,
            as_shared=False,
            can_write_lists=True,
            max_per_user=1,
        )
        assert result.errors and "limit" in result.errors[0]
        assert [spec.name for _row, spec in await load_lists(async_db)] == []

    async def test_a_key_is_ignored_when_importing_as_your_own(self, async_db, member_user):
        """Exporting the shared rules and importing them back as personal copies is legitimate."""
        await self._lolbas(async_db)
        await import_rules(async_db, [SPEC], user=member_user, as_shared=False, can_write_lists=False)
        await async_db.commit()
        row = (await async_db.execute(select(IntelRule))).scalar_one()
        assert row.builtin_key is None and row.is_builtin is False and row.owner_user_id == member_user.id

    async def test_the_secret_and_the_watch_flag_are_never_touched(self, async_db, member_user):
        await self._lolbas(async_db)
        row = IntelRule(owner_user_id=member_user.id, name=SPEC.name, query="x", entity_types="[]", webhook_secret_encrypted="enc", notify_job_watch=True)
        async_db.add(row)
        await async_db.commit()
        await import_rules(async_db, [SPEC], user=member_user, as_shared=False, can_write_lists=False)
        await async_db.commit()
        await async_db.refresh(row)
        assert row.webhook_secret_encrypted == "enc" and row.notify_job_watch is True and row.query == SPEC.criteria

    async def test_it_coins_the_tags_it_names(self, async_db, member_user):
        from app.models import TagDefinition

        await self._lolbas(async_db)
        await import_rules(async_db, [SPEC], user=member_user, as_shared=False, can_write_lists=False)
        await async_db.commit()
        assert (await async_db.execute(select(TagDefinition).where(TagDefinition.tag == "demo"))).scalar_one().color == "orange"
