"""A rule list can be fetched from a URL.

For the lists whose upstream moves — dynamic-DNS providers, paste sites, a TLD list — where
the alternative is someone remembering to paste a file in every few weeks, and nobody does.

The rule that matters most is the boring one: **a failed fetch keeps the old values.** A
feed that 404s, times out or answers with nothing must not empty a list that every rule on
the instance tests. Emptying it silently turns every rule that names it into a rule that
matches nothing, which is a detection outage nobody gets an alert about.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.intel.rule_list_fetch import FetchError, _strip_comments, fetch_list_values, is_due
from app.intel.rule_lists import ListSpec, load_lists, write_list

pytestmark = pytest.mark.anyio

NOW = datetime(2026, 9, 6, 12, 0, 0)


class TestWhenAListIsDue:
    def test_never_fetched_is_due(self):
        assert is_due(None, 24, now=NOW) is True

    def test_zero_hours_means_only_on_demand(self):
        """A real answer, not a disabled state: plenty of sources change once a year, and an
        interval that fetches anyway is a request someone else's server serves for nothing."""
        assert is_due(None, 0, now=NOW) is False
        assert is_due(NOW - timedelta(days=365), 0, now=NOW) is False

    def test_it_waits_out_the_interval(self):
        assert is_due(NOW - timedelta(hours=23), 24, now=NOW) is False
        assert is_due(NOW - timedelta(hours=24), 24, now=NOW) is True
        assert is_due(NOW - timedelta(hours=25), 24, now=NOW) is True


class TestParsingWhatComesBack:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("a\nb\nc", "a\nb\nc"),
            ("# a licence header\na\nb", "a\nb"),
            ("; ini-style\na", "a"),
            ("// c-style\na", "a"),
            ("\n\n  a  \n\n", "a"),
        ],
    )
    def test_comment_lines_are_dropped(self, raw, expected):
        """Every threat feed in the wild carries a header. Without this a list ends up with
        a licence in it, and `list:` then tests for the licence."""
        assert _strip_comments(raw) == expected

    def test_a_hash_inside_a_value_is_not_a_comment(self):
        assert _strip_comments("evil.com/#/path") == "evil.com/#/path"


class TestTheGuard:
    """The webhook guard, not the enrichment one — enrichment keys on a per-provider host
    allowlist, which is the wrong shape for an arbitrary feed URL."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "ftp://example.org/list.txt",
            "notaurl",
        ],
    )
    def test_it_refuses_rather_than_fetching(self, url):
        with pytest.raises(FetchError):
            fetch_list_values(url)

    def test_the_metadata_endpoint_is_refused_even_with_the_guard_relaxed(self, monkeypatch):
        """`RULE_LIST_REQUIRE_PUBLIC_HOST=false` allows an internal mirror. It does not
        allow instance credentials."""
        from app.config import settings

        monkeypatch.setattr(settings, "rule_list_require_public_host", False)
        with pytest.raises(FetchError):
            fetch_list_values("http://169.254.169.254/latest/meta-data/")

    def test_a_private_address_is_refused_by_default(self, monkeypatch):
        from app.config import settings

        monkeypatch.setattr(settings, "rule_list_require_public_host", True)
        with pytest.raises(FetchError):
            fetch_list_values("http://127.0.0.1:9/list.txt")

    def test_the_default_is_stricter_than_the_webhook_twin(self):
        """Deliberate: a feed is fetched on a schedule with nobody watching, and the reason
        to point one at an internal address is much rarer than for a webhook receiver.

        Read off the field, not off an instantiated `Settings()` — that picks up whatever
        the developer has in their own `.env`, and this is a claim about the default.
        """
        from app.config import Settings

        fields = Settings.model_fields
        assert fields["rule_list_require_public_host"].default is True
        assert fields["webhook_require_public_host"].default is False


class TestTheSweepKeepsWhatItHas:
    """The refresh sweep is worker code, so everything here is synchronous and the session
    is redirected the way `tests/test_periodic_bodies.py` does it."""

    @pytest.fixture()
    def a_fed_list(self, sync_db):
        from app.intel.rule_lists import write_list_sync
        from app.models import RuleList

        row = write_list_sync(sync_db, None, ListSpec(name="feed", values=("keep.me", "and.me")), seed_hash="seeded")
        row.source_url = "https://example.org/feed.txt"
        row.refresh_hours = 1
        sync_db.commit()
        assert isinstance(row, RuleList)
        return row

    def _values(self, sync_db, name: str) -> set[str]:
        from app.models import RuleList, RuleListValue

        row = sync_db.query(RuleList).filter_by(name=name).one()
        return {v.value for v in sync_db.query(RuleListValue).filter_by(list_id=row.id).all()}

    def test_a_failed_fetch_leaves_the_values_alone(self, sync_db, a_fed_list, monkeypatch):
        """The whole point. Emptying a list every rule tests is a detection outage nobody
        gets an alert about."""
        from app.workers import tasks

        def _boom(_url):
            raise FetchError("the feed answered HTTP 404")

        monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
        monkeypatch.setattr("app.intel.rule_list_fetch.fetch_list_values", _boom)

        detail = tasks._refresh_rule_lists_periodic_body()

        assert self._values(sync_db, "feed") == {"keep.me", "and.me"}, "a dead feed emptied the list"
        assert a_fed_list.last_fetch_ok is False
        assert "404" in (a_fed_list.last_fetch_error or "")
        assert detail == "0 refreshed, 1 failed"

    def test_an_unexpected_error_is_caught_too(self, sync_db, a_fed_list, monkeypatch):
        """A feed must never take the sweep down — the lists after it in the loop would
        silently stop refreshing, and nothing would say why."""
        from app.workers import tasks

        def _boom(_url):
            raise RuntimeError("something nobody predicted")

        monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
        monkeypatch.setattr("app.intel.rule_list_fetch.fetch_list_values", _boom)

        assert tasks._refresh_rule_lists_periodic_body() == "0 refreshed, 1 failed"
        assert self._values(sync_db, "feed") == {"keep.me", "and.me"}
        assert "RuntimeError" in (a_fed_list.last_fetch_error or "")

    def test_a_good_fetch_replaces_them(self, sync_db, a_fed_list, monkeypatch):
        from app.workers import tasks

        monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
        monkeypatch.setattr("app.intel.rule_list_fetch.fetch_list_values", lambda _url: ("new.one", "new.two", "new.three"))

        assert tasks._refresh_rule_lists_periodic_body() == "1 refreshed, 0 failed"
        assert self._values(sync_db, "feed") == {"new.one", "new.two", "new.three"}
        assert a_fed_list.last_fetch_ok is True
        assert a_fed_list.last_fetch_error is None
        assert a_fed_list.seed_hash is None, "a URL-backed list is an edited list; the seeder must leave it alone"

    def test_a_list_that_is_not_due_is_left_alone(self, sync_db, a_fed_list, monkeypatch):
        from app.database import utc_now_naive
        from app.workers import tasks

        a_fed_list.last_fetched_at = utc_now_naive()
        sync_db.commit()
        monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
        monkeypatch.setattr("app.intel.rule_list_fetch.fetch_list_values", lambda _url: ("should.not.appear",))

        assert tasks._refresh_rule_lists_periodic_body() == "nothing due"
        assert self._values(sync_db, "feed") == {"keep.me", "and.me"}

    def test_a_list_with_no_url_is_never_fetched(self, sync_db, monkeypatch):
        from app.intel.rule_lists import write_list_sync
        from app.workers import tasks

        write_list_sync(sync_db, None, ListSpec(name="manual", values=("a",)), seed_hash=None)
        sync_db.commit()
        monkeypatch.setattr(tasks, "get_sync_session", lambda: sync_db)
        monkeypatch.setattr("app.intel.rule_list_fetch.fetch_list_values", lambda _url: ("nope",))

        assert tasks._refresh_rule_lists_periodic_body() == "nothing due"
        assert self._values(sync_db, "manual") == {"a"}


def test_the_two_writers_agree():
    """`write_list` and `write_list_sync` are twins because async and sync SQLAlchemy do not
    mix. What must not drift is *what* they write."""
    import ast
    import inspect
    import textwrap

    from app.intel import rule_lists

    def body_shape(fn):
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        # Attribute assignments and the calls made, minus the await plumbing.
        return [(n.targets[0].attr if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Attribute) else None) for n in ast.walk(tree) if isinstance(n, ast.Assign)]

    assert body_shape(rule_lists.write_list) == body_shape(rule_lists.write_list_sync)


class TestTheFormAndTheButton:
    pytestmark = pytest.mark.anyio

    @pytest.fixture()
    async def a_list(self, async_db):
        await write_list(async_db, None, ListSpec(name="feed", values=("keep.me",)), seed_hash=None)
        await async_db.commit()
        return (await load_lists(async_db))[0][0]

    async def _reload(self, async_db, list_id: int):
        """Re-read the row after a request wrote it through its own session.

        The id is passed in rather than read off a held instance: `expire_all()` turns every
        attribute into a lazy load, and a lazy load on an expired instance outside the
        greenlet context is a `MissingGreenlet` — not a failure of the code under test.
        """
        from app.models import RuleList

        async_db.expire_all()
        return await async_db.get(RuleList, list_id)

    async def test_saving_a_url_records_it(self, admin_client, async_db, a_list):
        list_id = a_list.id
        resp = await admin_client.post(
            f"/intel/rules/lists/{list_id}/edit",
            data={"match": "exact", "description": "", "values": "keep.me", "source_url": "https://example.org/f.txt", "refresh_hours": "24"},
        )
        assert resp.status_code == 200
        row = await self._reload(async_db, list_id)
        assert row.source_url == "https://example.org/f.txt"
        assert row.refresh_hours == 24

    async def test_clearing_the_url_clears_the_history_with_it(self, admin_client, async_db, a_list):
        """ "Last fetched 3 h ago" under a list that is not fetched from anywhere is a
        lie with a timestamp on it."""
        from app.database import utc_now_naive

        a_list.source_url = "https://example.org/f.txt"
        a_list.refresh_hours = 24
        a_list.last_fetched_at = utc_now_naive()
        a_list.last_fetch_ok = False
        a_list.last_fetch_error = "boom"
        await async_db.commit()
        list_id = a_list.id

        await admin_client.post(
            f"/intel/rules/lists/{list_id}/edit",
            data={"match": "exact", "description": "", "values": "keep.me", "source_url": "", "refresh_hours": "24"},
        )
        row = await self._reload(async_db, list_id)
        assert row.source_url is None
        assert row.refresh_hours == 0
        assert row.last_fetched_at is None and row.last_fetch_ok is None and row.last_fetch_error is None

    async def test_the_interval_is_clamped_to_what_the_form_offers(self, admin_client, async_db, a_list):
        list_id = a_list.id
        await admin_client.post(
            f"/intel/rules/lists/{list_id}/edit",
            data={"match": "exact", "description": "", "values": "keep.me", "source_url": "https://example.org/f.txt", "refresh_hours": "99999"},
        )
        assert (await self._reload(async_db, list_id)).refresh_hours == 168

    async def test_refresh_needs_a_url(self, admin_client, a_list):
        assert (await admin_client.post(f"/intel/rules/lists/{a_list.id}/refresh")).status_code == 400

    async def test_a_member_may_not_refresh(self, member_client, a_list):
        assert (await member_client.post(f"/intel/rules/lists/{a_list.id}/refresh")).status_code == 403

    async def test_a_failed_refresh_reports_and_keeps_the_values(self, admin_client, async_db, a_list, monkeypatch):
        a_list.source_url = "https://example.org/f.txt"
        await async_db.commit()
        monkeypatch.setattr("app.intel.rule_list_fetch.fetch_list_values", lambda _u: (_ for _ in ()).throw(FetchError("the feed answered HTTP 404")))

        resp = await admin_client.post(f"/intel/rules/lists/{a_list.id}/refresh")
        assert resp.status_code == 200
        assert "could not be refreshed" in resp.text
        async_db.expire_all()
        lists = {spec.name: spec for _row, spec in await load_lists(async_db)}
        assert set(lists["feed"].values) == {"keep.me"}

    async def test_a_url_with_an_impossible_port_reports_instead_of_500ing(self, admin_client, async_db, a_list, monkeypatch):
        """A typo'd port saved fine, and Refresh then raised ValueError from `urlparse().port`
        past every handler — a 500, with the failure never recorded on the row."""
        monkeypatch.setattr("app.config.settings.rule_list_require_public_host", False)
        a_list.source_url = "http://localhost:99999/feed.txt"
        await async_db.commit()

        resp = await admin_client.post(f"/intel/rules/lists/{a_list.id}/refresh")
        assert resp.status_code == 200
        assert "could not be refreshed" in resp.text
        assert "port" in ((await self._reload(async_db, a_list.id)).last_fetch_error or "")

    async def test_a_good_refresh_replaces_the_values(self, admin_client, async_db, a_list, monkeypatch):
        a_list.source_url = "https://example.org/f.txt"
        await async_db.commit()
        monkeypatch.setattr("app.intel.rule_list_fetch.fetch_list_values", lambda _u: ("one.example", "two.example"))

        resp = await admin_client.post(f"/intel/rules/lists/{a_list.id}/refresh")
        assert "refreshed: 2 values" in resp.text
        async_db.expire_all()
        lists = {spec.name: spec for _row, spec in await load_lists(async_db)}
        assert set(lists["feed"].values) == {"one.example", "two.example"}
