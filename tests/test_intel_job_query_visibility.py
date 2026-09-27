"""Route tests for `job:` in the Intel search — above all, that it cannot read a job the
viewer may not see.

`?job=` was already the one dashboard input carrying job visibility, checked against
`visible_job_filter` before it reached the query, precisely because a job id is a reference
to someone else's submission. Putting the same filter in the free-text box reopens that hole
unless it gets the same check, so most of this file is about the private case rather than
the happy path.

`apply_entity_filters` is pure and has no viewer, so the check lives in the router and the
parser fails closed (an unresolved `job:` term matches nothing). Both halves are tested:
the router resolving correctly, and the parser refusing to be useful without it.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import AnalysisJob, Entity, EntityJobLink, IntelRule, JobStatus, LogFile, User, WorkflowDef

pytestmark = pytest.mark.anyio


async def _create_user(async_db, *, email: str, role: str = "member") -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=False, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


@pytest.fixture()
async def world(async_db):
    """Two jobs: one public, one private and owned by somebody else.

    Each has a distinctly-named entity, so a leak is visible in the rendered table rather
    than having to be inferred from a count.
    """
    async_db.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="a" * 64, size_bytes=10))
    async_db.add(LogFile(id=2, original_filename="b.evtx", stored_filename="f2.evtx", sha256="b" * 64, size_bytes=10))
    async_db.add(WorkflowDef(id=1, name="wf"))
    await async_db.commit()

    owner = await _create_user(async_db, email="owner@vis.example.com")
    viewer = await _create_user(async_db, email="viewer@vis.example.com")

    public = AnalysisJob(file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=False)
    private = AnalysisJob(file_id=2, workflow_id=1, status=JobStatus.COMPLETED, is_private=True, submitted_by_user_id=owner.id)
    pub_entity = Entity(value="public-marker.example", entity_type="domain", job_count=1)
    priv_entity = Entity(value="secret-marker.example", entity_type="domain", job_count=1)
    async_db.add_all([public, private, pub_entity, priv_entity])
    await async_db.commit()
    for obj in (public, private, pub_entity, priv_entity):
        await async_db.refresh(obj)

    async_db.add_all(
        [
            EntityJobLink(entity_id=pub_entity.id, job_id=public.id),
            EntityJobLink(entity_id=priv_entity.id, job_id=private.id),
        ]
    )
    await async_db.commit()
    return {"public": public, "private": private, "pub_entity": pub_entity, "priv_entity": priv_entity, "owner": owner, "viewer": viewer}


async def test_job_term_selects_that_jobs_entities(test_client, world):
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.get(f"/intel/entities-partial?q=job:{world['public'].id}")
    assert resp.status_code == 200
    assert "public-marker.example" in resp.text
    assert "secret-marker.example" not in resp.text


async def test_job_term_cannot_read_a_private_job(test_client, world):
    """The whole point of the check."""
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.get(f"/intel/entities-partial?q=job:{world['private'].id}")
    assert resp.status_code == 200
    assert "secret-marker.example" not in resp.text, "a private job's entities leaked through q=job:"
    assert "public-marker.example" not in resp.text, "the filter must match nothing, not be dropped"


async def test_the_owner_can_read_their_own_private_job(test_client, world):
    await _login(test_client, "owner@vis.example.com")
    resp = await test_client.get(f"/intel/entities-partial?q=job:{world['private'].id}")
    assert "secret-marker.example" in resp.text


async def test_an_admin_can_read_any_job(admin_client, world):
    resp = await admin_client.get(f"/intel/entities-partial?q=job:{world['private'].id}")
    assert "secret-marker.example" in resp.text


async def test_a_private_job_is_indistinguishable_from_a_missing_one(test_client, world):
    """Otherwise the error message itself becomes the id oracle the check exists to close."""
    await _login(test_client, "viewer@vis.example.com")
    private = await test_client.get(f"/intel/entities-partial?q=job:{world['private'].id}")
    missing = await test_client.get("/intel/entities-partial?q=job:99999")
    assert private.status_code == missing.status_code

    def _notice(text: str) -> str:
        """The rendered query-error banner, or '' when there isn't one."""
        marker = "not available"
        if marker not in text:
            return ""
        at = text.index(marker)
        return " ".join(text[max(0, at - 80) : at + 80].split())

    assert _notice(private.text) == _notice(missing.text), "the wording distinguishes private from nonexistent"


async def test_a_private_job_inside_an_or_does_not_widen_the_result(test_client, world):
    """`job:<public> OR job:<private>` must return only the public job's entities."""
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.get(f"/intel/entities-partial?q=job:{world['public'].id} OR job:{world['private'].id}")
    assert resp.status_code == 200
    assert "public-marker.example" in resp.text
    assert "secret-marker.example" not in resp.text


async def test_a_csv_of_ids_keeps_only_the_visible_ones(test_client, world):
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.get(f"/intel/entities-partial?q=job:{world['public'].id},{world['private'].id}")
    assert "public-marker.example" in resp.text
    assert "secret-marker.example" not in resp.text


async def test_boolean_query_runs_end_to_end_on_the_dashboard(test_client, world):
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.get(f"/intel/entities-partial?q=job:{world['public'].id} OR tag:nothing-here")
    assert resp.status_code == 200
    assert "public-marker.example" in resp.text


async def test_a_rejected_query_shows_the_error_and_no_rows(test_client, world):
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.get("/intel/entities-partial?q=re:/marker/ OR tag:x")
    assert resp.status_code == 200
    assert "cannot be combined with OR" in resp.text
    assert "public-marker.example" not in resp.text, "a rejected query must not render a plausible result set"


# ── watch rules ─────────────────────────────────────────────────────────────────────


def _rule_form(**over):
    form = {
        "name": "R",
        "query": "tag:a",
        "entity_types": "",
        "action_tag": "",
        "action_tag_color": "gray",
        "action_notify": "1",
        "webhook_url": "",
        "webhook_secret": "",
        "webhook_method": "POST",
        "webhook_headers": "",
        "webhook_enabled": "0",
    }
    form.update(over)
    return form


async def test_a_watch_rule_may_not_use_a_job_term(test_client, world):
    """The worker has no viewer to check visibility against, and a rule already runs against
    each job as it finishes — so `job:` there would be a way to ask "did *that* submission
    contain anything matching X" and get the answer as an alert."""
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.post("/intel/rules", data=_rule_form(query=f"job:{world['private'].id}"))
    assert resp.status_code == 400
    assert "job:" in resp.text


async def test_a_watch_rule_may_not_store_a_rejected_boolean_query(test_client, world, async_db):
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.post("/intel/rules", data=_rule_form(query="re:/^svc/ OR tag:x"))
    assert resp.status_code == 400
    assert (await async_db.scalar(select(IntelRule.id).where(IntelRule.query.contains("OR")))) is None


async def test_a_watch_rule_still_accepts_a_valid_boolean_query(test_client, world):
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.post("/intel/rules", data=_rule_form(query="tag:a OR tag:b"))
    assert resp.status_code == 200


async def test_type_term_filters_end_to_end(test_client, world):
    """The fixture's visible entity is a domain, so `type:` must include and exclude it."""
    await _login(test_client, "viewer@vis.example.com")

    hit = await test_client.get("/intel/entities-partial?q=type:domain")
    assert "public-marker.example" in hit.text

    miss = await test_client.get("/intel/entities-partial?q=type:hash")
    assert "public-marker.example" not in miss.text


async def test_type_term_composes_with_job_over_the_route(test_client, world):
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.get(f"/intel/entities-partial?q=type:domain AND job:{world['public'].id}")
    assert "public-marker.example" in resp.text


async def test_an_unknown_type_reports_the_error(test_client, world):
    await _login(test_client, "viewer@vis.example.com")
    resp = await test_client.get("/intel/entities-partial?q=type:bogus")
    assert "unknown type" in resp.text
