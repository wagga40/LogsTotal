"""The Intel search autocomplete: caret parsing (pure) and the suggest endpoint.

The caret logic lives in `queries.caret_token` rather than in JavaScript on purpose. It has
to agree with the parser about where a term begins and ends — `re:/^svc a/` is one token
despite the space, `(tag:a` is a group plus a term, `"a phrase"` is one token — and a second
implementation of those rules in JS would drift from the first. Sharing `scan_query` makes
that impossible, and puts the fiddly part somewhere it can be tested at all, since this
project ships no JavaScript test runner.

The endpoint half is mostly about `job:`: a completion list naming jobs the viewer cannot
open would be the enumeration oracle the `job:` term is careful not to be.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.intel.queries import caret_token, scan_query, tokenize_query
from app.models import AnalysisJob, Entity, EntityTag, JobStatus, LogFile, User, WorkflowDef

pytestmark = pytest.mark.anyio


# ── caret parsing ───────────────────────────────────────────────────────────────────


def _at(raw: str) -> dict:
    """Parse a query written with `|` marking the caret."""
    pos = raw.index("|")
    return caret_token(raw.replace("|", "", 1), pos)


@pytest.mark.parametrize(
    ("marked", "prefix", "fragment"),
    [
        ("tag:ap|", "tag:", "ap"),
        ("ta|", None, "ta"),
        ("|", None, ""),
        ("type:ip job:7|", "job:", "7"),
        ("type:ip| job:7", "type:", "ip"),
        ("(tag:a OR tag:|b)", "tag:", "b"),
        ("label:lol|bin tag:x", "label:", "lolbin"),
        ("-tag:noi|sy", "tag:", "noisy"),
        ("tag:a,b|", "tag:", "a,b"),
        ("attr:lol|", "attr:", "lol"),
        ("cidr:10.|", "cidr:", "10."),
    ],
)
def test_caret_identifies_the_term_being_typed(marked, prefix, fragment):
    token = _at(marked)
    assert token["prefix"] == prefix
    assert token["fragment"] == fragment


def test_the_replaced_span_covers_only_the_term_under_the_caret():
    raw = "type:ip tag:a OR job:7"
    token = caret_token(raw, raw.index("tag:a") + 5)
    assert raw[token["start"] : token["end"]] == "tag:a"
    # Splicing a completion in must leave everything else byte-identical.
    spliced = raw[: token["start"]] + "tag:apt28" + raw[token["end"] :]
    assert spliced == "type:ip tag:apt28 OR job:7"


def test_a_regex_with_spaces_is_one_token_not_two():
    """The whole reason this is not a `split(' ')` in JavaScript."""
    raw = "re:/^svc a/ tag:x"
    token = caret_token(raw, 6)
    assert token["prefix"] == "re:/"
    assert raw[token["start"] : token["end"]] == "re:/^svc a/"


def test_a_quoted_phrase_is_one_token():
    raw = '"quoted phrase" tag:x'
    token = caret_token(raw, 5)
    assert raw[token["start"] : token["end"]] == '"quoted phrase"'
    assert token["prefix"] is None


def test_parentheses_are_not_completable_terms():
    for raw, pos in (("(tag:a)", 0), ("(tag:a)", 7)):
        token = caret_token(raw, pos)
        assert token["text"] not in ("(", ")"), "a bare paren must never be offered a completion"


def test_uppercase_operators_offer_nothing():
    raw = "tag:a OR tag:b"
    token = caret_token(raw, 8)  # inside "OR"
    assert token["prefix"] is None
    assert token["fragment"] == "", "OR is grammar, not a partial key to complete"


def test_caret_beyond_the_last_token_starts_a_fresh_empty_term():
    raw = "tag:a "
    token = caret_token(raw, len(raw))
    assert token == {"start": 6, "end": 6, "text": "", "prefix": None, "fragment": ""}


@pytest.mark.parametrize("pos", [-5, 0, 3, 99])
def test_out_of_range_positions_are_clamped_not_crashed(pos):
    caret_token("tag:a", pos)


def test_scan_and_tokenize_come_from_one_scanner():
    """`tokenize_query` is the text view of `scan_query`; if they ever diverge the picker
    and the parser start disagreeing about token boundaries."""
    for raw in ("re:/^svc a/ tag:x", '"a phrase" -tag:b', "(tag:a OR tag:b) label:c", "job:1,2 type:ip"):
        assert [t for _s, _e, t in scan_query(raw, split_groups=True)] == tokenize_query(raw, split_groups=True)


def test_spans_index_the_original_string():
    raw = "(tag:a OR tag:b)"
    for start, end, _text in scan_query(raw, split_groups=True):
        assert 0 <= start <= end <= len(raw)


# ── the endpoint ────────────────────────────────────────────────────────────────────


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303)


@pytest.fixture()
async def world(async_db):
    async_db.add(LogFile(id=1, original_filename="public-log.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(LogFile(id=2, original_filename="secret-log.evtx", stored_filename="f2.evtx", sha256="b" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    await async_db.commit()

    owner = await _create_user(async_db, email="owner@sg.example.com")
    await _create_user(async_db, email="viewer@sg.example.com")

    public = AnalysisJob(submitted_filename="public-log.evtx", file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    private = AnalysisJob(submitted_filename="secret-log.evtx", file_id=2, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner.id)
    entity = Entity(value="host-1", entity_type="computer", job_count=1)
    async_db.add_all([public, private, entity])
    await async_db.commit()
    for obj in (public, private, entity):
        await async_db.refresh(obj)
    async_db.add(EntityTag(entity_id=entity.id, tag="apt28", color="red"))
    async_db.add(EntityTag(entity_id=entity.id, tag="approved", color="green"))
    await async_db.commit()
    return {"public": public, "private": private}


async def _suggest(client, q: str, pos: int | None = None) -> dict:
    resp = await client.get("/intel/search-suggest", params={"q": q, "pos": len(q) if pos is None else pos})
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_a_partial_key_offers_prefixes(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    data = await _suggest(test_client, "ta")
    assert [s["insert"] for s in data["suggestions"]] == ["tag:"]
    assert data["start"] == 0 and data["end"] == 2


async def test_an_empty_box_offers_every_prefix(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    inserts = [s["insert"] for s in (await _suggest(test_client, ""))["suggestions"]]
    assert {"tag:", "type:", "job:", "label:", "attr:", "cidr:", "re:/"} <= set(inserts)


async def test_tag_values_come_from_the_tag_vocabulary(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    data = await _suggest(test_client, "tag:ap")
    assert {s["insert"] for s in data["suggestions"]} == {"tag:apt28", "tag:approved"}


async def test_type_values_are_the_canonical_keys(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    inserts = [s["insert"] for s in (await _suggest(test_client, "type:ip"))["suggestions"]]
    assert "type:ip_address" in inserts


async def test_attr_values_come_from_the_filter_registry(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    inserts = [s["insert"] for s in (await _suggest(test_client, "attr:lol"))["suggestions"]]
    assert inserts == ["attr:lolbin"]


async def test_label_offers_both_system_labels_and_tags(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    inserts = [s["insert"] for s in (await _suggest(test_client, "label:"))["suggestions"]]
    assert "label:lolbin" in inserts, "system labels missing"
    assert "label:apt28" in inserts, "analyst tags missing"


async def test_job_suggestions_are_visibility_filtered(test_client, world):
    """The one that matters: a picker must not enumerate other people's submissions."""
    await _login(test_client, "viewer@sg.example.com")
    data = await _suggest(test_client, "job:")
    inserts = {s["insert"] for s in data["suggestions"]}
    details = " ".join(s["detail"] for s in data["suggestions"])
    assert f"job:{world['public'].id}" in inserts
    assert f"job:{world['private'].id}" not in inserts, "a private job was offered as a completion"
    assert "secret-log" not in details, "a private job's filename leaked through the picker"


async def test_the_owner_sees_their_own_private_job(test_client, world):
    await _login(test_client, "owner@sg.example.com")
    inserts = {s["insert"] for s in (await _suggest(test_client, "job:"))["suggestions"]}
    assert f"job:{world['private'].id}" in inserts


async def test_jobs_are_searchable_by_filename(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    inserts = {s["insert"] for s in (await _suggest(test_client, "job:public"))["suggestions"]}
    assert inserts == {f"job:{world['public'].id}"}


async def test_a_private_job_is_not_findable_by_its_filename(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    assert (await _suggest(test_client, "job:secret"))["suggestions"] == []


async def test_completions_preserve_negation(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    inserts = {s["insert"] for s in (await _suggest(test_client, "-tag:ap"))["suggestions"]}
    assert inserts == {"-tag:apt28", "-tag:approved"}


async def test_completions_extend_a_csv_rather_than_replacing_it(test_client, world):
    """Picking a second value must not silently discard the first."""
    await _login(test_client, "viewer@sg.example.com")
    inserts = {s["insert"] for s in (await _suggest(test_client, "tag:apt28,appr"))["suggestions"]}
    assert inserts == {"tag:apt28,approved"}


async def test_the_span_lets_the_client_edit_mid_query(test_client, world):
    q = "type:ip tag:ap OR job:1"
    await _login(test_client, "viewer@sg.example.com")
    data = await _suggest(test_client, q, pos=14)
    assert q[data["start"] : data["end"]] == "tag:ap"
    spliced = q[: data["start"]] + data["suggestions"][0]["insert"] + q[data["end"] :]
    assert spliced.startswith("type:ip tag:ap") and spliced.endswith(" OR job:1")


async def test_free_form_prefixes_offer_nothing(test_client, world):
    await _login(test_client, "viewer@sg.example.com")
    assert (await _suggest(test_client, "cidr:10.0"))["suggestions"] == []
    assert (await _suggest(test_client, "re:/^sv"))["suggestions"] == []


async def test_suggest_requires_member_access(test_client, user_client, world):
    assert (await user_client.get("/intel/search-suggest", params={"q": "tag:", "pos": 4})).status_code == 403
    assert (await test_client.get("/intel/search-suggest", params={"q": "tag:", "pos": 4})).status_code in (401, 403)


async def test_key_completions_are_distinguishable_from_value_completions(test_client, world):
    """`searchSuggest.pick()` decides whether to re-open the list or refresh the table by
    testing `insert.endsWith(':')`. That is a contract with this endpoint: a key completion
    must end in the separator and a value completion must not, or accepting `tag:` either
    refreshes the table on half a term or accepting `tag:apt28` leaves the list hanging."""
    await _login(test_client, "viewer@sg.example.com")

    keys = (await _suggest(test_client, ""))["suggestions"]
    assert keys, "no key completions offered"
    for item in keys:
        assert item["insert"].endswith(":") or item["insert"].endswith(":/"), item["insert"]

    for q in ("tag:ap", "type:ip", "job:", "attr:lol"):
        for item in (await _suggest(test_client, q))["suggestions"]:
            assert not item["insert"].endswith(":"), f"{q} produced a value that looks like a key: {item['insert']}"


async def test_every_offered_key_is_one_the_parser_understands(test_client, world):
    """A prefix the picker offers but `_parse_term` ignores would complete into a literal."""
    from app.intel.queries import _COMPLETABLE

    await _login(test_client, "viewer@sg.example.com")
    offered = {s["insert"] for s in (await _suggest(test_client, ""))["suggestions"]}
    assert offered <= set(_COMPLETABLE), offered - set(_COMPLETABLE)
