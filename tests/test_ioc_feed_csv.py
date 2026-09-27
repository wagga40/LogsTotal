"""`/intel/ioc-feed?format=csv` must defuse spreadsheet formulas, like the activity export.

The activity export has always run every cell through `csv_safe`; this feed wrote its rows
straight through `csv.DictWriter`. The values are attacker-controlled: `app/analytics.py`
constrains `ip_address`, `hash` and `domain` with regexes, but `user`, `computer`, `service`
and `task` are kept with nothing but a `.strip()`, and `app/intel/entities.py` persists them
verbatim for *every* job including anonymous uploads. So an anonymous log upload could put
`=cmd|…` in front of an analyst who clicks Export CSV on the Intel dashboard.

The whole row is mapped rather than the one field known to be reachable today — a column
added later must not have to remember this.
"""

from __future__ import annotations

import csv
import io

import pytest

from app.models import Entity

pytestmark = pytest.mark.anyio

#: What an attacker actually plants: DDE in a `user` value, which has no charset constraint.
PAYLOAD = "=cmd|' /C calc'!A0"


def _values(body: str) -> list[str]:
    return [row["value"] for row in csv.DictReader(io.StringIO(body))]


@pytest.fixture()
async def formula_entity(async_db) -> Entity:
    entity = Entity(value=PAYLOAD, entity_type="user", job_count=1)
    async_db.add(entity)
    await async_db.commit()
    await async_db.refresh(entity)
    return entity


async def test_a_formula_valued_entity_is_defused_in_the_csv_feed(member_client, formula_entity):
    resp = await member_client.get("/intel/ioc-feed?format=csv")
    assert resp.status_code == 200
    assert _values(resp.text) == ["'" + PAYLOAD]


@pytest.mark.parametrize("leader", ["=", "+", "-", "@", "\t", "\r"])
async def test_every_formula_leader_is_defused(member_client, async_db, leader):
    """`-` and `@` start a formula too, and Excel strips a leading tab or CR before parsing."""
    async_db.add(Entity(value=f"{leader}SUM(1)", entity_type="computer", job_count=1))
    await async_db.commit()

    resp = await member_client.get("/intel/ioc-feed?format=csv")
    assert resp.status_code == 200
    assert _values(resp.text) == [f"'{leader}SUM(1)"]


async def test_every_column_is_defused_not_just_the_value(member_client, monkeypatch):
    """Only `value` is reachable today; mapping the whole row is what keeps that true."""
    from app.routers import intel as intel_router

    poisoned = {
        "value": "=A1",
        "type": "+user",
        "first_seen": "-1",
        "last_seen": "@x",
        "job_count": "=1+1",
        "threat_categories": "=B2",
        "max_severity": "=C3",
    }

    async def _fake(*_args, **_kwargs):
        return [poisoned], []

    monkeypatch.setattr(intel_router, "_build_ioc_data", _fake)

    resp = await member_client.get("/intel/ioc-feed?format=csv")
    assert resp.status_code == 200
    row = next(iter(csv.DictReader(io.StringIO(resp.text))))
    assert row == {key: "'" + val for key, val in poisoned.items()}


async def test_the_json_feed_keeps_the_value_verbatim(member_client, formula_entity):
    """Defusing is a spreadsheet concern. A machine consumer must get the real observable —
    an apostrophe in the JSON, STIX or MISP rendering would corrupt the IOC it exports."""
    resp = await member_client.get("/intel/ioc-feed?format=json")
    assert resp.status_code == 200
    assert [ioc["value"] for ioc in resp.json()] == [PAYLOAD]
