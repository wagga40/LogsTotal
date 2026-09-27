"""Integration test: the Attributes card renders what the derivation computed.

The card comes from `attributes.attribute_keys` — the `attr:` keys this entity's stored
attributes satisfy — rather than from a hardcoded if/elif chain in the template, which
silently misses any key it has no branch for.

**Facts, not labels.** The header renders this entity's *tags*, and a built-in label is an
`EntityTag` written by a rule; this card is the derivation itself, which is a
different statement: it says what the engine computes, the tags say what a rule wrote down,
and the gap between them is how you spot a backfill that has not run.
"""

from __future__ import annotations

import pytest

from app.intel.attributes import compute_attributes
from app.json_utils import dumps as json_dumps


async def _entity(async_db, value, etype, attrs=None):
    from app.models import Entity

    e = Entity(value=value, entity_type=etype, job_count=1, attributes_json=json_dumps(attrs if attrs is not None else compute_attributes(value, etype)))
    async_db.add(e)
    await async_db.commit()
    return e


@pytest.mark.asyncio
async def test_lolbin_fact_renders_on_entity_page(member_client, async_db):
    e = await _entity(async_db, "certutil.exe", "executable")
    resp = await member_client.get(f"/intel/entities/{e.id}")
    assert resp.status_code == 200
    assert ">attr:lolbin<" in resp.text
    assert 'href="/intel?q=attr:lolbin"' in resp.text, "the chip must pivot to the filter it describes"


@pytest.mark.asyncio
async def test_gtfobin_fact_renders_on_entity_page(member_client, async_db):
    """The Overview tab renders gtfobin.

    Chips re-derived from `attributes_json` by hand can simply lack a branch for
    `is_gtfobin`, so a Unix living-off-the-land binary would look unremarkable on the tab an
    analyst reads first.
    """
    e = await _entity(async_db, "gtfo.test", "executable", {"is_lolbin": False, "is_gtfobin": True})
    resp = await member_client.get(f"/intel/entities/{e.id}")
    assert resp.status_code == 200
    assert ">attr:gtfobin<" in resp.text
    assert ">attr:lolbin<" not in resp.text


@pytest.mark.asyncio
async def test_private_ip_facts_render_subtype_first(member_client, async_db):
    e = await _entity(async_db, "10.0.0.1", "ip_address")
    resp = await member_client.get(f"/intel/entities/{e.id}")
    assert resp.status_code == 200
    assert resp.text.index(">attr:rfc1918<") < resp.text.index(">attr:private<")


@pytest.mark.asyncio
async def test_no_facts_means_no_card(member_client, async_db):
    e = await _entity(async_db, "plain.exe", "executable")
    resp = await member_client.get(f"/intel/entities/{e.id}")
    assert resp.status_code == 200
    assert "what the engine derived" not in resp.text
