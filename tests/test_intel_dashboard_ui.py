"""Integration tests for the redesigned Intel dashboard UI.

Covers the analyst-grade entity table (new columns, full sorting, attribute
chips) and the dashboard shell (consolidated filters, quick chips, exports).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest


def _utcnow():
    return datetime.now(UTC).replace(tzinfo=None)


@pytest.fixture()
async def seeded_entities(async_db):
    """Three entities with distinct job counts / timestamps / flags for sort assertions."""
    from app.json_utils import dumps
    from app.models import Entity

    lolbin = Entity(
        value="certutil.exe",
        entity_type="executable",
        job_count=12,
        watchlist=True,
        attributes_json=dumps({"is_lolbin": True}),
        first_seen_at=_utcnow() - timedelta(days=10),
        last_seen_at=_utcnow() - timedelta(hours=2),
    )
    ip = Entity(
        value="10.0.3.7",
        entity_type="ip_address",
        job_count=4,
        attributes_json=dumps({"version": "v4", "is_private": True, "category": "rfc1918"}),
        first_seen_at=_utcnow() - timedelta(days=3),
        last_seen_at=_utcnow() - timedelta(days=1),
    )
    dom = Entity(
        value="aaaa-old-domain.example",
        entity_type="domain",
        job_count=7,
        first_seen_at=_utcnow() - timedelta(days=30),
        last_seen_at=_utcnow() - timedelta(days=5),
    )
    async_db.add_all([lolbin, ip, dom])
    await async_db.commit()
    return {"lolbin": lolbin, "ip": ip, "dom": dom}


# ── Entity table partial ─────────────────────────────────────────────────────


async def test_table_shows_job_count_last_seen_and_attr_chips(member_client, seeded_entities):
    resp = await member_client.get("/intel/entities-partial")
    assert resp.status_code == 200
    body = resp.text
    assert "certutil.exe" in body
    # No derived chips here: the label column renders this entity's *tags*, and a built-in
    # label is one of those, written by a rule. The fixture seeds
    # `attributes_json` but no `EntityTag`, so it is the derivation that is deliberately
    # absent — `tests/test_builtin_label_rules.py` covers the rule that would write it.
    assert "LOLBin" not in body
    assert ">12<" in body  # job count cell
    assert "2h ago" in body  # relative last-seen
    assert "Last seen" in body  # new column header


def _order(body: str, values: list[str]) -> list[int]:
    return [body.index(v) for v in values]


async def test_sort_by_jobs_desc(member_client, seeded_entities):
    resp = await member_client.get("/intel/entities-partial?sort=jobs")
    pos = _order(resp.text, ["certutil.exe", "aaaa-old-domain.example", "10.0.3.7"])
    assert pos == sorted(pos)


async def test_sort_by_first_seen_asc(member_client, seeded_entities):
    resp = await member_client.get("/intel/entities-partial?sort=first_seen")
    pos = _order(resp.text, ["aaaa-old-domain.example", "certutil.exe", "10.0.3.7"])
    assert pos == sorted(pos)


async def test_sort_by_watchlist_first(member_client, seeded_entities):
    resp = await member_client.get("/intel/entities-partial?sort=watchlist")
    body = resp.text
    assert body.index("certutil.exe") < body.index("10.0.3.7")


async def test_type_filter_with_attr_query(member_client, seeded_entities):
    resp = await member_client.get("/intel/entities-partial?entity_type=executable&q=attr:lolbin")
    body = resp.text
    assert "certutil.exe" in body
    assert "10.0.3.7" not in body


async def test_empty_state_mentions_filters_when_advanced_set(member_client, seeded_entities):
    resp = await member_client.get("/intel/entities-partial?min_jobs=9999")
    assert "No entities match the current filters." in resp.text


# ── Dashboard shell ──────────────────────────────────────────────────────────


async def _seed_rules(async_db):
    from pathlib import Path

    from app.intel.rules_yaml import sync_rules_from_dir

    await sync_rules_from_dir(async_db, Path(__file__).resolve().parents[1] / "rules")
    await async_db.commit()


async def test_dashboard_has_type_select_and_label_chips(member_client, seeded_entities, async_db):
    await _seed_rules(async_db)
    resp = await member_client.get("/intel")
    assert resp.status_code == 200
    body = resp.text
    assert 'x-model="entityType"' in body  # single type select owns type filtering
    assert "tag:lolbin" in body  # a label chip
    assert "tag:rfc1918" in body
    # no clickable stat cards
    assert "entityType = entityType ===" not in body


async def test_label_chips_are_additive_not_destructive(member_client, seeded_entities, async_db):
    """A chip must toggle its own term, not overwrite the whole search box.

    Assigning `searchQuery = 'attr:<key>'` would let only one chip apply at a time, and
    clicking one would silently discard whatever the analyst had typed.
    """
    await _seed_rules(async_db)
    body = (await member_client.get("/intel")).text
    # The term rides in data-token (see test_no_alpine_expression_interpolates_a_tag_name).
    assert 'data-token="tag:lolbin" @click="toggleQueryToken($el.dataset.token)"' in body
    assert "hasQueryToken($el.dataset.token)" in body
    assert "searchQuery = searchQuery ===" not in body, "quick chips still overwrite the query"


async def test_label_chips_are_the_enabled_built_in_rules(member_client, seeded_entities, async_db):
    """One chip per enabled built-in, emitting the tag the rule writes — read from the rules
    themselves, so a rule an admin adds or imports is one click away, and a rule they switch
    off is not offered as a filter that can only match stale tags."""
    from sqlalchemy import select

    from app.models import IntelRule

    await _seed_rules(async_db)
    rules = (await async_db.execute(select(IntelRule).where(IntelRule.is_builtin.is_(True)))).scalars().all()
    off = next(r for r in rules if r.builtin_key == "sha1")
    off.enabled = False
    await async_db.commit()

    body = (await member_client.get("/intel")).text
    missing = [r.builtin_key for r in rules if r.enabled and r.scope == "entity" and f"tag:{r.action_tag}" not in body]
    assert not missing, f"enabled shared rules with no chip: {missing}"
    assert 'data-token="tag:sha1"' not in body


async def test_no_enabled_built_in_says_so(member_client, seeded_entities):
    assert "No shared rule is switched on." in (await member_client.get("/intel")).text


async def test_dashboard_has_export_menu(member_client, seeded_entities):
    resp = await member_client.get("/intel")
    body = resp.text
    for fmt in ("json", "csv", "stix", "misp"):
        assert f"/intel/ioc-feed?format={fmt}" in body
    assert "/intel/mitre-layer" in body


async def test_dashboard_has_sort_select(member_client, seeded_entities):
    resp = await member_client.get("/intel")
    body = resp.text
    assert 'x-model="sort"' in body
    assert "first_seen" in body


async def test_dashboard_stat_tiles(member_client, seeded_entities):
    resp = await member_client.get("/intel")
    body = resp.text
    for label in ("Total Entities", "Jobs Analyzed", "Watchlisted", "Allowlisted", "Cases", "Unacked Alerts"):
        assert label in body


# ── Entity detail page ───────────────────────────────────────────────────────


async def test_entity_detail_has_export_menu_and_chips(member_client, seeded_entities):
    eid = seeded_entities["lolbin"].id
    resp = await member_client.get(f"/intel/entities/{eid}")
    assert resp.status_code == 200
    body = resp.text
    assert f"/intel/entities/{eid}/stix" in body
    assert f"/intel/entities/{eid}/ioc-pack" in body
    assert f"/intel/entities/{eid}/mitre-layer" in body
    assert f"/intel/entities/{eid}/graph.graphml" in body
    # No inert derived chips in the header — see `test_intel_attributes_route.py`. The
    # Overview tab's Attributes card carries the long form instead.
    assert ">attr:lolbin<" in body  # the Attributes card: facts, not labels
    assert "/intel?type=executable" in body  # breadcrumb type link


# ── Cases ────────────────────────────────────────────────────────────────────


@pytest.fixture()
async def seeded_case(async_db, member_user, seeded_entities):
    from app.models import CaseEntityLink, InvestigationCase

    case = InvestigationCase(name="Lateral movement hunt", created_by_user_id=member_user.id, is_shared=True)
    async_db.add(case)
    await async_db.flush()
    async_db.add(CaseEntityLink(case_id=case.id, entity_id=seeded_entities["lolbin"].id, added_by_user_id=member_user.id))
    await async_db.commit()
    await async_db.refresh(case)
    return case


async def test_cases_list_shows_entity_and_job_counts(member_client, seeded_case):
    resp = await member_client.get("/intel/cases")
    assert resp.status_code == 200
    body = resp.text
    assert "1 entity" in body
    assert "0 jobs" in body


async def test_case_detail_has_export_menu(member_client, seeded_case):
    resp = await member_client.get(f"/intel/cases/{seeded_case.id}")
    assert resp.status_code == 200
    body = resp.text
    for suffix in ("stix", "misp", "ioc-pack", "graph.graphml"):
        assert f"/intel/cases/{seeded_case.id}/{suffix}" in body


# ── Saved searches (legacy shape keeps loading) ─────────────────────────────


async def test_legacy_saved_search_without_sort_still_renders(member_client, async_db, member_user):
    from app.models import SavedSearch

    async_db.add(
        SavedSearch(
            name="legacy",
            scope="entities",
            query_json='{"type": "executable", "q": "", "watchlist": 0}',
            created_by_user_id=member_user.id,
        )
    )
    await async_db.commit()

    resp = await member_client.get("/intel/saved-searches-partial?scope=entities")
    assert resp.status_code == 200
    assert "legacy" in resp.text
