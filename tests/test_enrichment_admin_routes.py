"""Route tests for /admin/enrichment.

Its structural twin `/admin/ai` is covered by `tests/test_ai_routes.py`. This is the form
that decides which observables leave the instance and to whom, so it earns the same.

The specific thing worth pinning is the entity-type control. A free-text CSV box parsed by
a comprehension that **silently drops** anything it does not recognise costs the whole form
for a typo and reports only "at least one valid entity_type is required" as a bare JSON
400. It is a checkbox group, and `constants.parse_entity_types` still accepts the CSV shape
so a scripted caller keeps working.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.constants import ENTITY_TYPES, parse_entity_types
from app.json_utils import loads as json_loads
from app.models import EnrichmentService, User

pytestmark = pytest.mark.anyio


async def _admin(async_db) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email="admin@enrich.example.com", password="pass123456", is_superuser=True, is_active=True, role="admin"))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"})
    assert resp.status_code in (200, 204)


@pytest.fixture()
async def admin_client(test_client, async_db):
    await _admin(async_db)
    await _login(test_client, "admin@enrich.example.com")
    return test_client


def _payload(**over) -> dict:
    base = {
        "name": "OTX",
        "provider_key": "",
        "entity_types": ["ip_address", "domain"],
        "link_template": "https://otx.example.com/{value}",
        "api_template": "",
        "api_method": "GET",
        "api_headers_json": "",
        "display_order": "100",
        "notes": "",
        "enabled": "1",
    }
    base.update(over)
    return base


# ── The shared parser ────────────────────────────────────────────────────────


class TestParseEntityTypes:
    """Tier 1. One function backs both admin forms that ask this question, rather than a
    comprehension each keyed off two different dicts of the same nine values."""

    def test_a_checkbox_group_posts_a_list(self):
        assert parse_entity_types(["ip_address", "domain"]) == ["ip_address", "domain"]

    def test_a_scripted_csv_caller_still_works(self):
        """The wire shape the text box produced. Accepting it is what makes this change
        invisible to anyone posting to the endpoint directly."""
        assert parse_entity_types("ip_address,domain") == ["ip_address", "domain"]
        assert parse_entity_types(["ip_address, domain"]) == ["ip_address", "domain"]

    def test_unknown_and_empty_tokens_are_dropped(self):
        assert parse_entity_types(["ip_address", "not_a_type", "", "  "]) == ["ip_address"]

    def test_duplicates_collapse_and_order_is_kept(self):
        assert parse_entity_types(["domain", "ip_address", "domain"]) == ["domain", "ip_address"]

    def test_nothing_in_nothing_out(self):
        assert parse_entity_types(None) == []
        assert parse_entity_types([]) == []
        assert parse_entity_types("") == []


# ── The form ─────────────────────────────────────────────────────────────────


async def test_the_form_offers_a_checkbox_per_type_not_a_text_box(admin_client):
    body = (await admin_client.get("/admin/enrichment")).text
    for t in ENTITY_TYPES:
        assert f'name="entity_types" value="{t}"' in body, f"{t} has no checkbox"
    assert 'name="entity_types" required' not in body, "the free-text CSV box is gone"


async def test_create_stores_the_ticked_types(admin_client, async_db):
    resp = await admin_client.post("/admin/enrichment", data=_payload(), follow_redirects=False)
    assert resp.status_code == 303

    svc = (await async_db.execute(select(EnrichmentService))).scalars().one()
    assert json_loads(svc.entity_types) == ["ip_address", "domain"]


async def test_create_still_accepts_a_csv_string(admin_client, async_db):
    """A scripted caller posting the CSV shape must not silently create a broken service."""
    resp = await admin_client.post("/admin/enrichment", data=_payload(entity_types="hash,executable"), follow_redirects=False)
    assert resp.status_code == 303

    svc = (await async_db.execute(select(EnrichmentService))).scalars().one()
    assert json_loads(svc.entity_types) == ["hash", "executable"]


async def test_creating_with_nothing_ticked_is_refused(admin_client, async_db):
    resp = await admin_client.post("/admin/enrichment", data=_payload(entity_types=[]), follow_redirects=False)
    assert resp.status_code == 400
    assert (await async_db.execute(select(EnrichmentService))).scalars().all() == []


async def test_editing_preserves_the_selection_in_the_form(admin_client, async_db):
    """The edit form is populated from the stored list, so a round trip must not lose a
    type — the CSV box rebuilt the string by hand, which is where a drift would show."""
    await admin_client.post("/admin/enrichment", data=_payload(entity_types=["hash"]), follow_redirects=False)
    svc = (await async_db.execute(select(EnrichmentService))).scalars().one()

    body = (await admin_client.get("/admin/enrichment")).text
    assert 'value="hash" checked' in body, "the stored selection must come back ticked"

    await admin_client.post(f"/admin/enrichment/{svc.id}", data=_payload(entity_types=["user", "computer"]), follow_redirects=False)
    await async_db.refresh(svc)
    assert json_loads(svc.entity_types) == ["user", "computer"]


async def test_the_edit_forms_save_button_starts_live(admin_client, async_db):
    """Save waits for at least one ticked type — `required` cannot say that about a group —
    and the count it waits on is seeded by the server.

    The create form's seed is the constant 0, so only this one can be wrong: get the Jinja
    expression wrong and Save is dead on arrival for every configured service, with the
    boxes visibly ticked beside it. A browser check cannot reach this branch on an instance
    with no services, which is exactly how it would ship unnoticed.
    """
    await admin_client.post("/admin/enrichment", data=_payload(entity_types=["hash", "domain"]), follow_redirects=False)

    body = (await admin_client.get("/admin/enrichment")).text
    assert 'x-data="{ chosen: 2 }"' in body, "the edit form did not seed its count from the stored types"
    assert 'x-data="{ chosen: 0 }"' in body, "the create form must start with nothing ticked"


async def test_a_non_admin_cannot_reach_the_page(test_client, async_db):
    user_db = SQLAlchemyUserDatabase(async_db, User)
    await UserManager(user_db).create(UserCreate(email="member@enrich.example.com", password="pass123456", is_superuser=False, is_active=True, role="member"))
    await _login(test_client, "member@enrich.example.com")
    assert (await test_client.get("/admin/enrichment")).status_code == 403
