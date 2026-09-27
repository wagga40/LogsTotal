"""The `case:read` Bearer scope.

The machine-readable case surfaces (index, detail, members, STIX, MISP, IOC pack) accept
either cookie auth or a scoped token. The load-bearing rule is that a token is a
*delegation* of its creator's access and never more: it must not reach a case, or a
private job inside a shared case, that its creator could not.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

from app.auth.api_tokens import generate_token
from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.database import utc_now_naive
from app.json_utils import dumps as json_dumps
from app.models import (
    AnalysisJob,
    ApiToken,
    CaseEntityLink,
    CaseJobLink,
    Entity,
    EntityJobLink,
    InvestigationCase,
    JobStatus,
    LogFile,
    LogType,
    User,
    WorkflowDef,
)

PRIVATE_FILENAME = "CASE_SECRET_private.evtx"
PUBLIC_FILENAME = "case_shared_public.evtx"


async def _user(async_db, *, email: str, is_superuser: bool = False) -> User:
    manager = UserManager(SQLAlchemyUserDatabase(async_db, User))
    return await manager.create(UserCreate(email=email, password="pass123456", is_active=True, is_superuser=is_superuser, role="admin" if is_superuser else "member"))


async def _token_for(async_db, owner: User | None, *, scopes: list[str]) -> str:
    plaintext, digest, prefix = generate_token()
    async_db.add(
        ApiToken(
            name=f"t-{prefix}",
            token_hash=digest,
            prefix=prefix,
            scopes_json=json_dumps(scopes),
            created_by_user_id=owner.id if owner else None,
        )
    )
    await async_db.commit()
    return plaintext


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
async def case_api_data(async_db):
    """Two members. `owner` has a shared case and a private case; the shared case holds
    a public job and a private job of the owner's."""
    owner = await _user(async_db, email="owner@caseapi.example.com")
    other = await _user(async_db, email="other@caseapi.example.com")

    wf = WorkflowDef(name="API WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()

    lf_pub = LogFile(original_filename=PUBLIC_FILENAME, stored_filename="ca_pub.evtx", sha256="1" * 64, size_bytes=10, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    lf_priv = LogFile(original_filename=PRIVATE_FILENAME, stored_filename="ca_priv.evtx", sha256="2" * 64, size_bytes=10, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([lf_pub, lf_priv])
    await async_db.flush()

    job_pub = AnalysisJob(
        submitted_filename=lf_pub.original_filename,
        effective_log_type=lf_pub.log_type,
        file_id=lf_pub.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
        is_private=False,
    )
    job_priv = AnalysisJob(
        submitted_filename=lf_priv.original_filename,
        effective_log_type=lf_priv.log_type,
        file_id=lf_priv.id,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
        is_private=True,
    )
    async_db.add_all([job_pub, job_priv])
    await async_db.flush()

    shared = InvestigationCase(name="Shared case", status="open", created_by_user_id=owner.id, is_shared=True)
    secret = InvestigationCase(name="Owner only case", status="open", created_by_user_id=owner.id, is_shared=False)
    async_db.add_all([shared, secret])
    await async_db.flush()

    ent = Entity(value="203.0.113.9", entity_type="ip_address", job_count=2)
    async_db.add(ent)
    await async_db.flush()
    async_db.add_all(
        [
            CaseEntityLink(case_id=shared.id, entity_id=ent.id, added_by_user_id=owner.id),
            CaseJobLink(case_id=shared.id, job_id=job_pub.id, added_by_user_id=owner.id),
            CaseJobLink(case_id=shared.id, job_id=job_priv.id, added_by_user_id=owner.id),
            EntityJobLink(entity_id=ent.id, job_id=job_pub.id, occurrence_count=1),
            EntityJobLink(entity_id=ent.id, job_id=job_priv.id, occurrence_count=1),
        ]
    )
    await async_db.commit()
    return {"owner": owner, "other": other, "shared": shared.id, "secret": secret.id}


# ── Scope enforcement ────────────────────────────────────────────────────────


async def test_no_credentials_are_rejected(test_client, case_api_data):
    resp = await test_client.get(f"/intel/cases/{case_api_data['shared']}/detail.json")
    assert resp.status_code == 401


async def test_wrong_scope_is_rejected(test_client, async_db, case_api_data):
    token = await _token_for(async_db, case_api_data["owner"], scopes=["ioc_feed:read"])
    resp = await test_client.get(f"/intel/cases/{case_api_data['shared']}/detail.json", headers=_auth(token))
    assert resp.status_code == 403


async def test_case_read_scope_is_accepted(test_client, async_db, case_api_data):
    token = await _token_for(async_db, case_api_data["owner"], scopes=["case:read"])
    resp = await test_client.get(f"/intel/cases/{case_api_data['shared']}/detail.json", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.json()["name"] == "Shared case"


@pytest.mark.parametrize(
    "path",
    ["/detail.json", "/entities.json", "/stix", "/misp", "/ioc-pack"],
)
async def test_every_case_export_accepts_the_token(test_client, async_db, case_api_data, path):
    token = await _token_for(async_db, case_api_data["owner"], scopes=["case:read"])
    resp = await test_client.get(f"/intel/cases/{case_api_data['shared']}{path}", headers=_auth(token))
    assert resp.status_code == 200, f"{path}: {resp.text[:200]}"


async def test_case_index_accepts_the_token(test_client, async_db, case_api_data):
    token = await _token_for(async_db, case_api_data["owner"], scopes=["case:read"])
    resp = await test_client.get("/intel/cases/list.json", headers=_auth(token))
    assert resp.status_code == 200
    assert {c["name"] for c in resp.json()} == {"Shared case", "Owner only case"}


# ── A token never exceeds its creator's visibility ───────────────────────────


async def test_token_cannot_reach_a_case_its_creator_cannot(test_client, async_db, case_api_data):
    """`other` is a member but not the owner, and the case is unshared."""
    token = await _token_for(async_db, case_api_data["other"], scopes=["case:read"])
    resp = await test_client.get(f"/intel/cases/{case_api_data['secret']}/detail.json", headers=_auth(token))
    assert resp.status_code == 404


async def test_token_index_is_scoped_to_its_creator(test_client, async_db, case_api_data):
    token = await _token_for(async_db, case_api_data["other"], scopes=["case:read"])
    resp = await test_client.get("/intel/cases/list.json", headers=_auth(token))
    assert resp.status_code == 200
    assert {c["name"] for c in resp.json()} == {"Shared case"}, "an unshared case leaked to a non-owner's token"


async def test_ownerless_token_sees_shared_cases_only(test_client, async_db, case_api_data):
    """Defensive: a token whose creator is gone must degrade to shared-only, not crash."""
    token = await _token_for(async_db, None, scopes=["case:read"])
    resp = await test_client.get("/intel/cases/list.json", headers=_auth(token))
    assert resp.status_code == 200
    assert {c["name"] for c in resp.json()} == {"Shared case"}

    denied = await test_client.get(f"/intel/cases/{case_api_data['secret']}/detail.json", headers=_auth(token))
    assert denied.status_code == 404


async def test_private_job_inside_a_shared_case_is_not_exposed(test_client, async_db, case_api_data):
    """The owner linked a private job into a shared case; a non-owner's token must not
    see its filename — the same rule the HTML case page applies."""
    token = await _token_for(async_db, case_api_data["other"], scopes=["case:read"])
    resp = await test_client.get(f"/intel/cases/{case_api_data['shared']}/detail.json", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.text
    assert PUBLIC_FILENAME in body
    assert PRIVATE_FILENAME not in body


async def test_owner_token_does_see_their_own_private_job(test_client, async_db, case_api_data):
    token = await _token_for(async_db, case_api_data["owner"], scopes=["case:read"])
    resp = await test_client.get(f"/intel/cases/{case_api_data['shared']}/detail.json", headers=_auth(token))
    assert PRIVATE_FILENAME in resp.text


# ── Cookie auth still works ──────────────────────────────────────────────────


async def test_cookie_auth_still_reaches_the_json_surfaces(test_client, case_api_data):
    login = await test_client.post("/auth/cookie/login", data={"username": "owner@caseapi.example.com", "password": "pass123456"}, follow_redirects=False)
    assert login.status_code in (200, 204, 303)
    resp = await test_client.get(f"/intel/cases/{case_api_data['shared']}/detail.json")
    assert resp.status_code == 200
    assert resp.json()["id"] == case_api_data["shared"]


async def test_status_filter_widens_the_index(test_client, async_db, case_api_data):
    closed = InvestigationCase(name="Closed case", status="closed", created_by_user_id=case_api_data["owner"].id, is_shared=True, closed_at=utc_now_naive())
    async_db.add(closed)
    await async_db.commit()

    token = await _token_for(async_db, case_api_data["owner"], scopes=["case:read"])
    default = await test_client.get("/intel/cases/list.json", headers=_auth(token))
    assert "Closed case" not in {c["name"] for c in default.json()}

    widened = await test_client.get("/intel/cases/list.json", params={"status": "all"}, headers=_auth(token))
    assert "Closed case" in {c["name"] for c in widened.json()}
