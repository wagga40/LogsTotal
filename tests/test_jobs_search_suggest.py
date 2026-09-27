"""Autocomplete on the jobs search box.

The jobs grammar shipped sharing the entity grammar's tokenizer and none of its manners:
one box completed `tag:` as you typed and the other, parsing the same shapes, said nothing.
An analyst who learns a dialect on one list should not find the other one mute.

Two things carry real risk and are most of what is pinned here.

**The caret parsing is server-side, and the prefix set is per-grammar.** `caret_token` has
to agree with the parser about where a term begins and ends — a quoted phrase is one token
despite its space, and editing one term of a long query must replace only that term — so it
takes the prefix set as an argument rather than being reimplemented for the second grammar.

**Completion lists are an enumeration surface.** `id:` and `sha256:` are deliberately never
offered: a list of job numbers or file hashes hands over exactly what the terms themselves
are careful not to leak. `tag:` is member-only because the jobs list hides tags from anyone
else, and everything job-derived runs through the visibility filter.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.intel.queries import caret_token
from app.jobs_query import COMPLETABLE_PREFIXES, IS_FLAGS, PREFIX_HELP, SYNTAX_HELP, parse_jobs_query
from app.models import AnalysisJob, JobStatus, JobTag, LogFile, LogType, TaskResult, TaskStatus, User, WorkflowDef

pytestmark = pytest.mark.anyio


# ── Tier 1: caret parsing against this grammar's keys ───────────────────────────────────


def _at(marked: str) -> dict:
    """Parse a query written with `|` marking the caret."""
    pos = marked.index("|")
    return caret_token(marked.replace("|", "", 1), pos, COMPLETABLE_PREFIXES)


@pytest.mark.parametrize(
    ("marked", "prefix", "fragment"),
    [
        ("status:fa|", "status:", "fa"),
        ("sta|", None, "sta"),
        ("tag:apt29,c|", "tag:", "apt29,c"),
        ("-is:priv|", "is:", "priv"),
        ('"my report" status:|', "status:", ""),
        ("status:failed sev:cr|", "sev:", "cr"),
        # `job:` belongs to the other grammar; here it is a filename search, so there is no
        # key to complete and the whole token is the fragment.
        ("job:12|", None, "job:12"),
    ],
)
def test_the_caret_reads_this_grammars_keys(marked: str, prefix: str | None, fragment: str):
    token = _at(marked)
    assert token["prefix"] == prefix
    assert token["fragment"] == fragment


def test_editing_one_term_leaves_the_rest_alone():
    """The span is what a completion replaces, so it must bound only the term under the
    caret — otherwise accepting a suggestion eats the query around it."""
    token = _at("status:failed sev:cr| tag:apt29")
    raw = "status:failed sev:cr tag:apt29"
    assert raw[token["start"] : token["end"]] == "sev:cr"


def test_every_offered_prefix_parses_and_is_documented():
    """The picker, the parser and the help panel are three views of one list. A key the
    picker offers and the parser ignores silently produces a term that matches nothing."""
    advertised = " ".join(f"{syntax} {meaning}" for syntax, meaning in SYNTAX_HELP)
    for prefix in COMPLETABLE_PREFIXES:
        assert prefix in advertised, f"{prefix} is offered but appears nowhere in the help"
        parsed = parse_jobs_query(f"{prefix}x")
        assert parsed["terms"], f"{prefix} produced no term at all"


def test_the_help_table_covers_every_offered_prefix():
    assert {p for p, _ in PREFIX_HELP} == set(COMPLETABLE_PREFIXES)


def test_id_and_hash_are_never_offered():
    """They parse, and are deliberately not completable: a completion list of job numbers or
    file hashes is an enumeration oracle."""
    assert "id:" not in COMPLETABLE_PREFIXES
    assert "sha256:" not in COMPLETABLE_PREFIXES
    assert parse_jobs_query("id:42")["terms"][0]["kind"] == "id"


# ── Tier 3: the endpoint ────────────────────────────────────────────────────────────────


async def _user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    return await UserManager(user_db).create(UserCreate(email=email, password="pass123456", is_active=True, role=role))


@pytest.fixture()
async def data(async_db):
    async_db.add(LogFile(id=1, original_filename="sysmon.evtx", stored_filename="s.evtx", sha256="a" * 64, size_bytes=10, log_type=LogType.EVTX))
    async_db.add_all([WorkflowDef(id=1, name="Windows Full Analysis"), WorkflowDef(id=2, name="quick")])
    await async_db.commit()
    owner = await _user(async_db, email="own@sug.example.com")
    await _user(async_db, email="mem@sug.example.com")
    await _user(async_db, email="plain@sug.example.com", role="user")

    public = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    private = AnalysisJob(file_id=1, workflow_id=2, status=JobStatus.FAILED, is_private=True, submitted_by_user_id=owner.id)
    async_db.add_all([public, private])
    await async_db.commit()
    for j in (public, private):
        await async_db.refresh(j)
    async_db.add_all(
        [
            JobTag(job_id=public.id, tag="shared", color="red"),
            JobTag(job_id=private.id, tag="hidden", color="blue"),
            TaskResult(job_id=public.id, tool_name="zircolite", status=TaskStatus.COMPLETED),
            TaskResult(job_id=private.id, tool_name="chainsaw", status=TaskStatus.COMPLETED),
            TaskResult(job_id=public.id, tool_name="Computing analytics", status=TaskStatus.COMPLETED),
        ]
    )
    await async_db.commit()
    return {"public": public, "private": private}


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"})
    assert resp.status_code in (200, 204)


async def _suggest(client, q: str, pos: int | None = None) -> dict:
    resp = await client.get("/jobs/search-suggest", params={"q": q, "pos": len(q) if pos is None else pos})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _labels(payload: dict) -> list[str]:
    return [i["label"] for i in payload["suggestions"]]


def _inserts(payload: dict) -> list[str]:
    return [i["insert"] for i in payload["suggestions"]]


class TestItCompletes:
    async def test_a_partial_key_offers_the_keys(self, test_client, data):
        assert _labels(await _suggest(test_client, "sta")) == ["status:"]

    async def test_a_committed_key_offers_its_values(self, test_client, data):
        assert "failed" in _labels(await _suggest(test_client, "status:"))

    async def test_values_narrow_as_you_type(self, test_client, data):
        assert _labels(await _suggest(test_client, "status:comp")) == ["completed"]

    async def test_a_flag_carries_what_it_asks(self, test_client, data):
        payload = await _suggest(test_client, "is:wat")
        assert _labels(payload) == ["watched"]
        assert payload["suggestions"][0]["detail"] == IS_FLAGS["watched"]

    async def test_a_workflow_with_a_space_is_quoted(self, test_client, data):
        """The tokenizer splits on whitespace, so an unquoted name would insert three terms
        and match nothing."""
        assert _inserts(await _suggest(test_client, "workflow:Win")) == ['workflow:"Windows Full Analysis"']

    async def test_free_form_terms_offer_their_shapes(self, test_client, data):
        """There is nothing to enumerate for a count or a date, and the shapes are the part
        people forget."""
        assert ">10" in _labels(await _suggest(test_client, "findings:"))
        assert "7d" in _labels(await _suggest(test_client, "after:"))


class TestItKeepsWhatWasTyped:
    async def test_a_csv_is_extended_not_replaced(self, test_client, data):
        """Every multi-valued term here is any-of, so picking a second value must not
        discard the first."""
        assert _inserts(await _suggest(test_client, "status:failed,comp")) == ["status:failed,completed"]

    async def test_a_negation_survives(self, test_client, data):
        assert _inserts(await _suggest(test_client, "-status:comp")) == ["-status:completed"]

    async def test_the_span_covers_only_the_edited_term(self, test_client, data):
        q = "tag:x status:comp sev:high"
        payload = await _suggest(test_client, q, pos=len("tag:x status:comp"))
        assert q[payload["start"] : payload["end"]] == "status:comp"


class TestItDoesNotLeak:
    async def test_tags_are_member_only(self, test_client, data):
        """The jobs list hides tags from a `user`, so offering the vocabulary here would
        hand over what the page withholds."""
        assert _labels(await _suggest(test_client, "tag:")) == []
        await _login(test_client, "plain@sug.example.com")
        assert _labels(await _suggest(test_client, "tag:")) == []

    async def test_the_tag_key_is_not_even_offered_to_a_non_member(self, test_client, data):
        assert "tag:" not in _labels(await _suggest(test_client, ""))
        await _login(test_client, "mem@sug.example.com")
        assert "tag:" in _labels(await _suggest(test_client, ""))

    async def test_a_member_sees_tags_from_jobs_they_can_open(self, test_client, data):
        await _login(test_client, "mem@sug.example.com")
        labels = _labels(await _suggest(test_client, "tag:"))
        assert "shared" in labels
        assert "hidden" not in labels, "a tag that exists only on someone else's private job"

    async def test_tools_come_from_visible_jobs_only(self, test_client, data):
        await _login(test_client, "mem@sug.example.com")
        labels = _labels(await _suggest(test_client, "tool:"))
        assert "zircolite" in labels
        assert "chainsaw" not in labels, "only ran on a private job"

    async def test_post_processing_tasks_are_not_tools(self, test_client, data):
        """`TaskResult` also holds "Computing analytics" and "File similarity". They are real
        rows, so `tool:` matches them — offering them is a lie about what ran on the log."""
        await _login(test_client, "mem@sug.example.com")
        assert "Computing analytics" not in _labels(await _suggest(test_client, "tool:"))

    @pytest.mark.parametrize("typed", ["id:", "sha256:", "id:4", "sha256:9f"])
    async def test_ids_and_hashes_are_never_enumerated(self, test_client, data, typed):
        await _login(test_client, "mem@sug.example.com")
        assert _labels(await _suggest(test_client, typed)) == []


class TestItSurvivesJunk:
    @pytest.mark.parametrize("q", ["", "   ", "%", "tag:%", "re:/(a+)+/", '"unclosed', "((((", "-" * 200])
    async def test_it_answers_rather_than_erroring(self, test_client, data, q):
        payload = await _suggest(test_client, q)
        assert "suggestions" in payload

    async def test_a_caret_past_the_end_is_clamped(self, test_client, data):
        payload = await _suggest(test_client, "status:", pos=9999)
        assert payload["start"] <= payload["end"] <= 7
