"""The jobs-list search grammar.

Tier 1 for the parser, Tier 3 for the filter, and the two halves are tested separately for
the same reason `app/jobs_query.py` is a pure module: a grammar that parses correctly and
compiles to the wrong SQL fails silently, as a list that is subtly wrong rather than a page
that errors.

The invariant worth naming: **every term compiles to SQL**. Intel supports `re:` and `cidr:`
by fetching a 1000-row window and filtering in Python, which makes its totals approximate.
The jobs pager is the app's main affordance, so a term that forced that here would be a
regression in something people use constantly to buy a search nobody asked for.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import func, select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.jobs_query import IS_FLAGS, SYNTAX_HELP, apply_jobs_query, describe, parse_jobs_query, query_errors
from app.models import AnalysisJob, JobStatus, JobTag, LogFile, LogType, User, WorkflowDef

pytestmark = pytest.mark.anyio


# ── Tier 1: the parser ───────────────────────────────────────────────────────


def _kinds(q):
    return [t["kind"] for t in parse_jobs_query(q)["terms"]]


class TestParsing:
    def test_a_bare_word_is_a_filename_search(self):
        assert _kinds("report.evtx") == ["text"]

    def test_whitespace_means_and(self):
        assert _kinds("status:failed sev:critical") == ["status", "severity"]

    def test_quotes_hold_a_phrase_together(self):
        terms = parse_jobs_query('"my report.evtx"')["terms"]
        assert terms == [{"kind": "text", "value": "my report.evtx", "negated": False}]

    def test_a_leading_dash_negates_any_term(self):
        terms = parse_jobs_query("-tag:reviewed -is:private")["terms"]
        assert all(t["negated"] for t in terms)

    def test_tags_are_normalised_the_way_the_write_path_normalises_them(self):
        """`tag:APT28` must find a stored `apt28`, or the filter silently misses."""
        assert parse_jobs_query("tag:APT28,C2")["terms"][0]["tags"] == ["apt28", "c2"]

    def test_comparisons(self):
        assert parse_jobs_query("findings:>10")["terms"][0]["amount"] == (">", 10.0, 0.0)
        assert parse_jobs_query("findings:0")["terms"][0]["amount"] == ("=", 0.0, 0.0)
        assert parse_jobs_query("findings:5..50")["terms"][0]["amount"] == ("range", 5.0, 50.0)

    def test_relative_dates(self):
        """ "What broke this week" is the question people actually bring to a job list."""
        from app.database import utc_now_naive

        elapsed = utc_now_naive() - parse_jobs_query("after:7d")["terms"][0]["when"]
        assert 6.99 < elapsed.total_seconds() / 86400 < 7.01

    def test_an_unknown_prefix_is_a_filename_search_not_an_error(self):
        """Paths and rule ids contain colons. Refusing them would make the commonest search
        fail on its most distinctive input."""
        terms = parse_jobs_query("C:/Windows/System32")["terms"]
        assert terms[0]["kind"] == "text"

    def test_a_bad_value_is_reported_rather_than_raised(self):
        parsed = parse_jobs_query("status:nonsense")
        assert parsed["invalid"] is True
        assert query_errors(parsed) == ["unknown status: nonsense"]

    @pytest.mark.parametrize(
        "raw",
        [
            "after:99999999d",  # past datetime.min
            "after:9999999999999d",  # past timedelta's C int
            "before:5000000w",
            "after:²d",  # str.isdigit() is True for '²'; int() refuses it
            "before:¹²h",
            "id:²",
            "id:①",
            "id:99999999999999999999",  # past int8 on SQLite, past int4 on PostgreSQL
            "id:2147483648",
        ],
    )
    def test_a_value_the_database_cannot_take_is_an_error_not_an_exception(self, raw):
        """`parse_jobs_query` promises it never raises, and `/jobs` is anonymous and polls
        every 5s, so an exception here is a 500 on a shareable URL."""
        parsed = parse_jobs_query(raw)
        assert parsed["invalid"] is True, parsed

    @pytest.mark.parametrize("raw", ["findings:nan", "findings:inf", "findings:-inf..5"])
    def test_a_non_finite_count_is_not_a_number(self, raw):
        assert parse_jobs_query(raw)["invalid"] is True

    def test_the_term_count_is_bounded(self):
        from app.jobs_query import MAX_TERMS

        assert len(parse_jobs_query(" ".join(f"tag:t{i}" for i in range(40)))["terms"]) == MAX_TERMS

    def test_every_advertised_flag_parses(self):
        """The help panel and the parser read the same list, so a flag cannot be documented
        and unimplemented — or implemented and undiscoverable."""
        for flag in IS_FLAGS:
            parsed = parse_jobs_query(f"is:{flag}")
            assert not query_errors(parsed), f"is:{flag} is advertised but not understood"

    def test_the_help_is_not_stale(self):
        syntaxes = {s.split(":")[0] for s, _ in SYNTAX_HELP if ":" in s and not s.startswith('"')}
        for prefix in ("tag", "status", "type", "workflow", "sev", "tool", "findings", "after", "id", "sha256", "is"):
            assert prefix in syntaxes or f"-{prefix}" in syntaxes, f"{prefix}: is understood but undocumented"


class TestChips:
    def test_a_term_reads_back_as_it_was_typed(self):
        for q in ("tag:apt29,c2", "status:failed", "findings:>10", "-is:private", "id:42"):
            chip = describe(parse_jobs_query(q)["terms"][0])
            assert chip == q, f"{q} rendered as {chip}"


# ── Tier 3: the filter ───────────────────────────────────────────────────────


@pytest.fixture()
async def jobs(async_db):
    user_db = SQLAlchemyUserDatabase(async_db, User)
    owner = await UserManager(user_db).create(UserCreate(email="owner@jq.example.com", password="pass123456", is_superuser=False, is_active=True, role="member"))
    async_db.add(LogFile(id=1, original_filename="server01.evtx", stored_filename="a", sha256="ab" * 32, size_bytes=1, log_type=LogType.EVTX))
    async_db.add(LogFile(id=2, original_filename="auth.log", stored_filename="b", sha256="cd" * 32, size_bytes=1, log_type=LogType.SYSLOG))
    async_db.add(WorkflowDef(id=1, name="Windows Full"))
    async_db.add(WorkflowDef(id=2, name="Linux Syslog"))
    await async_db.commit()

    win = AnalysisJob(
        submitted_filename="server01.evtx",
        effective_log_type=LogType.EVTX,
        file_id=1,
        workflow_id=1,
        status=JobStatus.COMPLETED,
        total_findings=42,
        is_private=False,
        submitted_by_user_id=owner.id,
    )
    lin = AnalysisJob(submitted_filename="auth.log", effective_log_type=LogType.SYSLOG, file_id=2, workflow_id=2, status=JobStatus.FAILED, total_findings=0, is_private=False)
    async_db.add_all([win, lin])
    await async_db.commit()
    for o in (win, lin, owner):
        await async_db.refresh(o)
    async_db.add(JobTag(job_id=win.id, tag="apt29", color="red"))
    await async_db.commit()
    return {"win": win, "lin": lin, "owner": owner}


async def _ids(async_db, q, viewer_id=None):
    stmt = apply_jobs_query(select(AnalysisJob.id), parse_jobs_query(q), viewer_id=viewer_id)
    return set((await async_db.execute(stmt)).scalars().all())


class TestFiltering:
    @pytest.mark.parametrize(
        ("query", "expect"),
        [
            ("server01", "win"),
            ("server*", "win"),
            ("tag:apt29", "win"),
            ("status:failed", "lin"),
            ("type:syslog", "lin"),
            ("workflow:windows", "win"),
            ("findings:>10", "win"),
            ("findings:0", "lin"),
            ("is:clean", "lin"),
            ("is:hits", "win"),
            ("id:{win}", "win"),
            ("sha256:abab", "win"),
            ("-tag:apt29", "lin"),
            ("-status:failed", "win"),
        ],
    )
    async def test_each_term_narrows_to_the_right_job(self, async_db, jobs, query, expect):
        q = query.format(win=jobs["win"].id, lin=jobs["lin"].id)
        assert await _ids(async_db, q) == {jobs[expect].id}, q

    async def test_terms_compose_with_and(self, async_db, jobs):
        assert await _ids(async_db, "type:evtx findings:>10") == {jobs["win"].id}
        assert await _ids(async_db, "type:evtx status:failed") == set()

    async def test_is_mine_is_empty_for_a_signed_out_viewer(self, async_db, jobs):
        """Dropping the term would silently show them everybody's jobs."""
        assert await _ids(async_db, "is:mine", viewer_id=None) == set()
        assert await _ids(async_db, "is:mine", viewer_id=jobs["owner"].id) == {jobs["win"].id}

    async def test_a_bad_term_matches_nothing_rather_than_everything(self, async_db, jobs):
        """The analyst typed something. Silently widening to the whole list is the one
        behaviour that misleads them about what they are looking at."""
        assert await _ids(async_db, "status:nonsense") == set()

    @pytest.mark.parametrize("query", ["-status:nonsense", "-type:nonsense", "-severity:nonsense", "-findings:x", "-is:nonsense"])
    async def test_a_negated_bad_term_does_not_widen_either(self, async_db, jobs, query):
        """The guard above is applied per-term *before* negation, because `~false()` is
        `WHERE TRUE`: negating a typo would hand back the entire unfiltered list, which
        is the precise failure the unnegated case exists to prevent."""
        assert await _ids(async_db, query) == set(), query

    async def test_a_bad_term_still_poisons_an_otherwise_valid_query(self, async_db, jobs):
        """`query_errors` says why the list is empty. Dropping the bad term instead would
        answer a question the analyst did not ask."""
        assert await _ids(async_db, "type:evtx -status:nonsense") == set()
        assert query_errors(parse_jobs_query("type:evtx -status:nonsense"))

    async def test_the_same_builder_works_on_a_count(self, async_db, jobs):
        """The pager runs it against `count()`. A JOIN would multiply rows there and the
        page numbers would quietly stop matching the list."""
        stmt = apply_jobs_query(select(func.count(AnalysisJob.id)), parse_jobs_query("tag:apt29"), viewer_id=None)
        assert await async_db.scalar(stmt) == 1


# ── The route ────────────────────────────────────────────────────────────────


async def _login(client, email):
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"})
    assert resp.status_code in (200, 204)


class TestTheRoute:
    async def test_the_page_and_its_poll_apply_the_same_query(self, test_client, async_db, jobs):
        """The twin-query trap again: a filter on the page and not on the 5s poll is
        invisible until something is running."""
        await _login(test_client, "owner@jq.example.com")
        page = (await test_client.get("/jobs?q=status:failed")).text
        partial = (await test_client.get("/jobs/table-partial?q=status:failed")).text

        for body in (page, partial):
            assert f"/jobs/{jobs['lin'].id}" in body
            assert f"/jobs/{jobs['win'].id}" not in body

    async def test_the_query_rides_the_poll_url_and_the_pager(self, test_client, async_db, jobs):
        await _login(test_client, "owner@jq.example.com")
        body = (await test_client.get("/jobs?q=is:hits")).text
        assert "q=is%3Ahits" in body, "the filter must survive a poll and a page turn"

    async def test_tags_and_q_merge_rather_than_one_winning(self, test_client, async_db, jobs):
        """`?tags=` is what a chip click produces and `?q=tag:` is what someone types.
        Supplying both means any-of, which is what any-of means everywhere else."""
        await _login(test_client, "owner@jq.example.com")
        body = (await test_client.get("/jobs?tags=apt29&q=tag:nothing")).text
        assert f"/jobs/{jobs['win'].id}" in body

    @pytest.mark.parametrize("q", ["after:99999999d", "id:%C2%B2", "id:99999999999999999999", "findings:nan"])
    async def test_an_unparseable_number_never_500s_the_page_or_its_poll(self, test_client, async_db, jobs, q):
        for path in (f"/jobs?q={q}", f"/jobs/table-partial?q={q}"):
            resp = await test_client.get(path)  # anonymous, as a shared link would be
            assert resp.status_code == 200, (path, resp.status_code)

    async def test_an_ignored_term_is_said_out_loud(self, test_client, async_db, jobs):
        """A term that matched nothing and a term that was not understood look identical in
        the results."""
        await _login(test_client, "owner@jq.example.com")
        body = (await test_client.get("/jobs?q=status:nonsense")).text
        assert "Ignored:" in body
        assert "unknown status: nonsense" in body

    async def test_the_query_never_widens_past_what_the_viewer_may_see(self, test_client, async_db, jobs):
        """Search is not an escape from `visible_job_filter`."""
        private = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=jobs["owner"].id)
        async_db.add(private)
        await async_db.commit()
        await async_db.refresh(private)

        body = (await test_client.get("/jobs?q=is:private")).text  # anonymous
        assert f"/jobs/{private.id}" not in body


class TestThePrefixSetMatchesTheParser:
    """`PREFIXES` is read by the condition editor to colour a prefix it recognises.

    The parser itself has no list — it is an if-chain over `kind`, and an unknown
    `word:value` is deliberately a *filename* search rather than an error. So nothing about
    a new prefix fails loudly when the constant is not updated: the term keeps working and
    merely renders as plain text in the editor, which is the sort of thing nobody reports.
    This walks the chain and compares.
    """

    def _kinds_the_parser_handles(self) -> set[str]:
        import ast
        import inspect
        import textwrap

        from app import jobs_query

        tree = ast.parse(textwrap.dedent(inspect.getsource(jobs_query.parse_jobs_query)))
        kinds: set[str] = set()
        for node in ast.walk(tree):
            # `kind == "tag"` and `kind in ("after", "before")` are the two shapes used.
            if not isinstance(node, ast.Compare) or not isinstance(node.left, ast.Name) or node.left.id != "kind":
                continue
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                    kinds.add(comparator.value)
                elif isinstance(comparator, ast.Tuple):
                    kinds.update(e.value for e in comparator.elts if isinstance(e, ast.Constant))
        return kinds

    def test_every_prefix_the_parser_understands_is_declared(self):
        from app.jobs_query import PREFIXES

        declared = {p.rstrip(":") for p in PREFIXES}
        missing = self._kinds_the_parser_handles() - declared
        assert not missing, f"parse_jobs_query handles {sorted(missing)}, which PREFIXES does not declare"

    def test_no_declared_prefix_is_a_fiction(self):
        from app.jobs_query import PREFIXES

        extra = {p.rstrip(":") for p in PREFIXES} - self._kinds_the_parser_handles()
        assert not extra, f"PREFIXES declares {sorted(extra)}, which the parser gives no meaning to"

    def test_everything_completable_is_also_parseable(self):
        from app.jobs_query import COMPLETABLE_PREFIXES, PREFIXES

        assert set(COMPLETABLE_PREFIXES) <= set(PREFIXES)
