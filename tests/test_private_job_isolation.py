"""Private jobs must not leak cross-user via side channels.

Covers the similarity, correlation, intel entity-listing, and cases surfaces — each joins
to AnalysisJob and needs the is_private visibility filter.
"""

from __future__ import annotations

import pytest
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy import select

from app.auth.schemas import UserCreate
from app.auth.users import UserManager
from app.models import (
    AnalysisJob,
    CaseJobLink,
    Entity,
    EntityJobLink,
    Finding,
    FindingEntityLink,
    JobStatus,
    LogFile,
    LogType,
    Severity,
    TaskResult,
    TaskStatus,
    User,
    WorkflowDef,
)

PRIVATE_FILENAME = "TOP_SECRET_private.evtx"
PUBLIC_FILENAME = "shared_public.evtx"
RULE_SIG = "abc-rule-123:high"
PUBLIC_TECHNIQUE = "T1059"
PRIVATE_TECHNIQUE = "T1486"


async def _create_user(async_db, *, email: str, role: str = "member", is_superuser: bool = False) -> User:
    user_db = SQLAlchemyUserDatabase(async_db, User)
    manager = UserManager(user_db)
    return await manager.create(UserCreate(email=email, password="pass123456", is_superuser=is_superuser, is_active=True, role=role))


async def _login(client, email: str) -> None:
    resp = await client.post("/auth/cookie/login", data={"username": email, "password": "pass123456"}, follow_redirects=False)
    assert resp.status_code in (200, 204, 303), resp.text


def _finding(task_result_id: int) -> Finding:
    return Finding(task_result_id=task_result_id, rule_id="abc-rule-123", rule_name="Bad Rule", severity=Severity.HIGH, count=1, rule_signature=RULE_SIG)


@pytest.fixture()
async def isolation_data(async_db):
    wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
    async_db.add(wf)
    await async_db.flush()

    owner = await _create_user(async_db, email="owner@iso.example.com", role="member")
    other = await _create_user(async_db, email="other@iso.example.com", role="member")

    lf_pub = LogFile(original_filename=PUBLIC_FILENAME, stored_filename="p_pub.evtx", sha256="a" * 64, size_bytes=1024, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    lf_priv = LogFile(original_filename=PRIVATE_FILENAME, stored_filename="p_priv.evtx", sha256="b" * 64, size_bytes=1024, log_type=LogType.EVTX, detected_type=LogType.EVTX)
    async_db.add_all([lf_pub, lf_priv])
    await async_db.flush()

    job_pub = AnalysisJob(
        file_id=lf_pub.id,
        submitted_filename=PUBLIC_FILENAME,
        effective_log_type=LogType.EVTX,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
        is_private=False,
    )
    job_priv = AnalysisJob(
        file_id=lf_priv.id,
        submitted_filename=PRIVATE_FILENAME,
        effective_log_type=LogType.EVTX,
        workflow_id=wf.id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=owner.id,
        is_private=True,
    )
    async_db.add_all([job_pub, job_priv])
    await async_db.flush()

    tr_pub = TaskResult(job_id=job_pub.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=1)
    tr_priv = TaskResult(job_id=job_priv.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=1)
    async_db.add_all([tr_pub, tr_priv])
    await async_db.flush()
    async_db.add_all([_finding(tr_pub.id), _finding(tr_priv.id)])

    entity = Entity(value="10.9.9.9", entity_type="ip_address", job_count=2)
    async_db.add(entity)
    await async_db.flush()
    async_db.add_all(
        [
            EntityJobLink(entity_id=entity.id, job_id=job_pub.id, occurrence_count=1),
            EntityJobLink(entity_id=entity.id, job_id=job_priv.id, occurrence_count=1),
        ]
    )

    await async_db.commit()
    for obj in (owner, other, job_pub, job_priv, entity, wf):
        await async_db.refresh(obj)
    return {"owner": owner, "other": other, "job_pub": job_pub, "job_priv": job_priv, "entity": entity, "wf": wf}


# ── Correlated findings (anonymous-reachable) ────────────────────────────────


async def test_correlated_hides_private_job_from_anonymous(test_client, isolation_data):
    job_pub = isolation_data["job_pub"]
    resp = await test_client.get(f"/jobs/{job_pub.id}/correlated", params={"rule_signature": RULE_SIG})
    assert resp.status_code == 200
    assert PRIVATE_FILENAME not in resp.text


async def test_correlated_shows_private_job_to_owner(test_client, isolation_data):
    await _login(test_client, "owner@iso.example.com")
    job_pub = isolation_data["job_pub"]
    resp = await test_client.get(f"/jobs/{job_pub.id}/correlated", params={"rule_signature": RULE_SIG})
    assert resp.status_code == 200
    assert PRIVATE_FILENAME in resp.text


async def test_correlated_hides_private_job_from_other_member(test_client, isolation_data):
    await _login(test_client, "other@iso.example.com")
    job_pub = isolation_data["job_pub"]
    resp = await test_client.get(f"/jobs/{job_pub.id}/correlated", params={"rule_signature": RULE_SIG})
    assert resp.status_code == 200
    assert PRIVATE_FILENAME not in resp.text


# ── Intel entity job listing (member-gated) ──────────────────────────────────


async def test_entity_jobs_partial_hides_private_from_non_owner(test_client, isolation_data):
    await _login(test_client, "other@iso.example.com")
    entity = isolation_data["entity"]
    resp = await test_client.get(f"/intel/entities/{entity.id}/jobs-partial")
    assert resp.status_code == 200
    assert PUBLIC_FILENAME in resp.text
    assert PRIVATE_FILENAME not in resp.text
    assert f'/jobs/{isolation_data["job_priv"].id}"' not in resp.text


async def test_entity_jobs_partial_shows_private_to_owner(test_client, isolation_data):
    await _login(test_client, "owner@iso.example.com")
    entity = isolation_data["entity"]
    resp = await test_client.get(f"/intel/entities/{entity.id}/jobs-partial")
    assert resp.status_code == 200
    assert PRIVATE_FILENAME in resp.text


# ── Intel entity MITRE tab + Navigator layer (member-gated) ──────────────────
#
# ``_entity_technique_counts`` aggregates Finding.tags through FindingEntityLink.
# It needs the visible-job filter every sibling per-entity route applies, or the
# technique IDs, the per-technique event counts, and the Navigator layer's
# ``comment`` strings are derived from other members' private jobs.


@pytest.fixture()
async def entity_mitre_findings(async_db, isolation_data):
    """Tag one finding per job with a distinct technique, linked to the shared entity."""
    entity = isolation_data["entity"]
    tids = {}
    for key, tid in (("job_pub", PUBLIC_TECHNIQUE), ("job_priv", PRIVATE_TECHNIQUE)):
        tr_id = await async_db.scalar(select(TaskResult.id).where(TaskResult.job_id == isolation_data[key].id))
        finding = Finding(
            task_result_id=tr_id,
            rule_id=f"rule-{tid}",
            rule_name=f"Rule {tid}",
            severity=Severity.HIGH,
            count=1,
            tags=f'["attack.{tid.lower()}"]',
        )
        async_db.add(finding)
        await async_db.flush()
        async_db.add(FindingEntityLink(finding_id=finding.id, entity_id=entity.id))
        tids[key] = tid
    await async_db.commit()
    return tids


async def test_entity_mitre_partial_hides_private_techniques_from_non_owner(test_client, isolation_data, entity_mitre_findings):
    await _login(test_client, "other@iso.example.com")
    entity = isolation_data["entity"]
    resp = await test_client.get(f"/intel/entities/{entity.id}/mitre-partial")
    assert resp.status_code == 200
    assert PUBLIC_TECHNIQUE in resp.text
    assert PRIVATE_TECHNIQUE not in resp.text


async def test_entity_mitre_partial_shows_private_techniques_to_owner(test_client, isolation_data, entity_mitre_findings):
    await _login(test_client, "owner@iso.example.com")
    entity = isolation_data["entity"]
    resp = await test_client.get(f"/intel/entities/{entity.id}/mitre-partial")
    assert resp.status_code == 200
    assert PUBLIC_TECHNIQUE in resp.text
    assert PRIVATE_TECHNIQUE in resp.text


async def test_entity_mitre_layer_excludes_private_techniques_from_non_owner(test_client, isolation_data, entity_mitre_findings):
    await _login(test_client, "other@iso.example.com")
    entity = isolation_data["entity"]
    resp = await test_client.get(f"/intel/entities/{entity.id}/mitre-layer")
    assert resp.status_code == 200
    ids = {t["techniqueID"] for t in resp.json()["techniques"]}
    assert ids == {PUBLIC_TECHNIQUE}


# ── Cases: cannot pull another user's private job into a case ─────────────────


async def test_case_add_rejects_unviewable_private_job(test_client, async_db, isolation_data):
    await _login(test_client, "other@iso.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Case A", "is_shared": "1"}, follow_redirects=False)
    assert create.status_code == 303
    case_id = int(create.headers["location"].rstrip("/").split("/")[-1])

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(isolation_data["job_priv"].id)}, follow_redirects=False)
    assert resp.status_code == 404

    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id))
    assert link is None


async def test_case_add_allows_owner_private_job(test_client, async_db, isolation_data):
    await _login(test_client, "owner@iso.example.com")
    create = await test_client.post("/intel/cases", data={"name": "Owner Case"}, follow_redirects=False)
    case_id = int(create.headers["location"].rstrip("/").split("/")[-1])

    resp = await test_client.post(f"/intel/cases/{case_id}/jobs", data={"job_id": str(isolation_data["job_priv"].id)}, follow_redirects=False)
    assert resp.status_code == 303
    link = await async_db.scalar(select(CaseJobLink).where(CaseJobLink.case_id == case_id))
    assert link is not None


# ── Similar files (function-level; requires the tlsh backend) ─────────────────


async def test_similar_files_hides_private_from_non_owner(async_db, isolation_data):
    import os

    tlsh = pytest.importorskip("tlsh")
    digest = tlsh.hash(os.urandom(4096))
    if not digest or digest == "TNULL":
        pytest.skip("tlsh backend produced no digest for random data")

    # Both files share the same digest (distance 0), so each is a candidate for the other.
    for lf in (await async_db.execute(select(LogFile))).scalars().all():
        lf.tlsh_hash = digest
    await async_db.commit()

    from app.similarity.hasher import find_similar_files_async

    pub_file_id = isolation_data["job_pub"].file_id
    owner = isolation_data["owner"]
    other = isolation_data["other"]

    seen_by_other = await find_similar_files_async(async_db, digest, exclude_file_id=pub_file_id, viewer=other)
    assert all(sf.original_filename != PRIVATE_FILENAME for sf in seen_by_other)

    seen_by_owner = await find_similar_files_async(async_db, digest, exclude_file_id=pub_file_id, viewer=owner)
    assert any(sf.original_filename == PRIVATE_FILENAME for sf in seen_by_owner)


# ── Resubmit must not downgrade privacy ──────────────────────────────────────


async def test_resubmit_inherits_is_private_from_prior_job(test_client, async_db, isolation_data):
    """Re-running a private submission must not publish it.

    Built without `is_private`, the new AnalysisJob would take the column's `False` default
    and the findings of a deliberately private upload would become visible to every
    anonymous visitor — a downgrade the submitter never asked for and would only notice by
    reading the results page as a logged-out user.
    """
    owner = isolation_data["owner"]
    job_priv = isolation_data["job_priv"]
    await _login(test_client, owner.email)

    resp = await test_client.post(
        "/jobs/resubmit",
        data={"file_id": str(job_priv.file_id), "workflow_id": str(isolation_data["wf"].id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text

    new_job = (await async_db.execute(select(AnalysisJob).where(AnalysisJob.file_id == job_priv.file_id).order_by(AnalysisJob.id.desc()).limit(1))).scalar_one()
    assert new_job.id != job_priv.id, "expected a freshly created job"
    assert new_job.is_private is True, "resubmitting a private job published it"


async def test_resubmit_of_public_job_stays_public(test_client, async_db, isolation_data):
    owner = isolation_data["owner"]
    job_pub = isolation_data["job_pub"]
    await _login(test_client, owner.email)

    resp = await test_client.post(
        "/jobs/resubmit",
        data={"file_id": str(job_pub.file_id), "workflow_id": str(isolation_data["wf"].id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text

    new_job = (await async_db.execute(select(AnalysisJob).where(AnalysisJob.file_id == job_pub.file_id).order_by(AnalysisJob.id.desc()).limit(1))).scalar_one()
    assert new_job.is_private is False


async def test_resubmit_prefers_the_requesters_own_prior_job(test_client, async_db, isolation_data):
    """Uploads are deduplicated by SHA-256, so one LogFile can carry jobs from several
    users. Inheriting from "the newest job the requester can see" then let another
    user's public job flip a private resubmission public."""
    owner = isolation_data["owner"]
    job_priv = isolation_data["job_priv"]

    # A second member later submits the same file publicly — newer than the owner's.
    other_public = AnalysisJob(
        file_id=job_priv.file_id,
        workflow_id=isolation_data["wf"].id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=isolation_data["other"].id,
        is_private=False,
    )
    async_db.add(other_public)
    await async_db.commit()

    await _login(test_client, owner.email)
    resp = await test_client.post(
        "/jobs/resubmit",
        data={"file_id": str(job_priv.file_id), "workflow_id": str(isolation_data["wf"].id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text

    new_job = (await async_db.execute(select(AnalysisJob).where(AnalysisJob.file_id == job_priv.file_id).order_by(AnalysisJob.id.desc()).limit(1))).scalar_one()
    assert new_job.is_private is True, "another user's public job downgraded this resubmission"


async def test_admin_resubmit_does_not_inherit_another_users_privacy(test_client, async_db, isolation_data, admin_user):
    """An admin sees every job, so "newest visible" could be someone else's private one
    and would quietly privatise the admin's own resubmission.

    The stranger's job is stamped an hour into the future so it is *unambiguously* the
    newest. Without that this test passed only by accident: SQLite's CURRENT_TIMESTAMP has
    one-second resolution, so both rows normally share a created_at and the ORDER BY tie
    broke in the older row's favour. Any change that made the suite a little slower pushed
    the two inserts into different seconds and the assertion flipped.
    """
    from datetime import timedelta

    from app.database import utc_now_naive

    job_pub = isolation_data["job_pub"]

    someone_elses_private = AnalysisJob(
        file_id=job_pub.file_id,
        workflow_id=isolation_data["wf"].id,
        status=JobStatus.COMPLETED,
        submitted_by_user_id=isolation_data["owner"].id,
        is_private=True,
        created_at=utc_now_naive() + timedelta(hours=1),
    )
    async_db.add(someone_elses_private)
    await async_db.commit()

    login = await test_client.post("/auth/cookie/login", data={"username": admin_user.email, "password": "testpass123"}, follow_redirects=False)
    assert login.status_code in (200, 204, 303), login.text
    resp = await test_client.post(
        "/jobs/resubmit",
        data={"file_id": str(job_pub.file_id), "workflow_id": str(isolation_data["wf"].id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text

    new_job = (await async_db.execute(select(AnalysisJob).where(AnalysisJob.file_id == job_pub.file_id).order_by(AnalysisJob.id.desc()).limit(1))).scalar_one()
    assert new_job.is_private is False


async def test_admin_resubmit_of_a_privately_held_file_stays_private(test_client, async_db, isolation_data, admin_user):
    """An admin has no job of their own on a member's private upload, so there was no
    source to inherit from and the re-run took the public default: the findings of a file
    only ever submitted privately became readable by every anonymous visitor. With no
    public job on the file, its content has never been public and the re-run must not be."""
    job_priv = isolation_data["job_priv"]

    login = await test_client.post("/auth/cookie/login", data={"username": admin_user.email, "password": "testpass123"}, follow_redirects=False)
    assert login.status_code in (200, 204, 303), login.text
    resp = await test_client.post(
        "/jobs/resubmit",
        data={"file_id": str(job_priv.file_id), "workflow_id": str(isolation_data["wf"].id)},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text

    new_job = (await async_db.execute(select(AnalysisJob).where(AnalysisJob.file_id == job_priv.file_id).order_by(AnalysisJob.id.desc()).limit(1))).scalar_one()
    assert new_job.id != job_priv.id, "expected a freshly created job"
    assert new_job.submitted_by_user_id == admin_user.id
    assert new_job.is_private is True, "an admin re-run published a privately held file"


# ── Watchlist acknowledgement is scoped to visible jobs ──────────────────────


@pytest.fixture()
async def rule_alerts(async_db, isolation_data):
    """One unacknowledged alert per member, on the job each of them owns rules about.

    The bell reads `intel_rule_match`. A match belongs to a rule, which belongs to one
    person, so cross-user isolation is structural rather than a filter that can be
    forgotten on the write path — a shared stream would let one member's "acknowledge all"
    dismiss another member's private-job alert.
    """
    from app.models import IntelRule, IntelRuleMatch

    entity = isolation_data["entity"]
    owner_rule = IntelRule(name="owner rule", owner_user_id=isolation_data["owner"].id, query=entity.value)
    other_rule = IntelRule(name="other rule", owner_user_id=isolation_data["other"].id, query=entity.value)
    async_db.add_all([owner_rule, other_rule])
    await async_db.flush()
    owner_match = IntelRuleMatch(rule_id=owner_rule.id, entity_id=entity.id, job_id=isolation_data["job_priv"].id)
    other_match = IntelRuleMatch(rule_id=other_rule.id, entity_id=entity.id, job_id=isolation_data["job_pub"].id)
    async_db.add_all([owner_match, other_match])
    await async_db.commit()
    for o in (owner_match, other_match):
        await async_db.refresh(o)
    return {"owner_match": owner_match, "other_match": other_match}


async def test_ack_all_leaves_other_members_alerts_untouched(test_client, async_db, isolation_data, rule_alerts):
    """ "Acknowledge all" must only ever touch the actor's own rules."""
    from app.models import IntelRuleMatch

    await _login(test_client, isolation_data["other"].email)
    resp = await test_client.post("/intel/watchlist-events/ack-all")
    assert resp.status_code == 200

    owner_match = await async_db.get(IntelRuleMatch, rule_alerts["owner_match"].id)
    other_match = await async_db.get(IntelRuleMatch, rule_alerts["other_match"].id)
    await async_db.refresh(owner_match)
    await async_db.refresh(other_match)
    assert owner_match.acknowledged_at is None, "ack-all dismissed another member's alert"
    assert other_match.acknowledged_at is not None, "ack-all did not acknowledge the actor's own alert"


async def test_owner_can_ack_their_own_alert(test_client, async_db, isolation_data, rule_alerts):
    from app.models import IntelRuleMatch

    await _login(test_client, isolation_data["owner"].email)
    resp = await test_client.post(f"/intel/watchlist-events/{rule_alerts['owner_match'].id}/ack")
    assert resp.status_code == 200
    row = await async_db.get(IntelRuleMatch, rule_alerts["owner_match"].id)
    await async_db.refresh(row)
    assert row.acknowledged_at is not None


async def test_acking_another_members_alert_is_a_404(test_client, async_db, isolation_data, rule_alerts):
    """Existence-oracle discipline: not-yours is indistinguishable from not-there."""
    from app.models import IntelRuleMatch

    await _login(test_client, isolation_data["other"].email)
    resp = await test_client.post(f"/intel/watchlist-events/{rule_alerts['owner_match'].id}/ack")
    assert resp.status_code == 404
    row = await async_db.get(IntelRuleMatch, rule_alerts["owner_match"].id)
    await async_db.refresh(row)
    assert row.acknowledged_at is None


async def test_bell_count_is_per_user(test_client, isolation_data, rule_alerts):
    await _login(test_client, isolation_data["other"].email)
    assert (await test_client.get("/intel/watchlist-events-partial?count_only=1")).text == "1"
    await _login(test_client, isolation_data["owner"].email)
    assert (await test_client.get("/intel/watchlist-events-partial?count_only=1")).text == "1"


@pytest.fixture()
async def private_only_neighbour(async_db, isolation_data):
    """An entity reachable from the shared one *only* through the private job.

    Without it these exports look identical whether or not the job filter applies, so the
    tests could not fail.
    """
    neighbour = Entity(value="10.6.6.6", entity_type="ip_address", job_count=1)
    async_db.add(neighbour)
    await async_db.flush()
    async_db.add(EntityJobLink(entity_id=neighbour.id, job_id=isolation_data["job_priv"].id, occurrence_count=1))
    await async_db.commit()
    await async_db.refresh(neighbour)
    return neighbour


async def test_entity_ioc_pack_excludes_private_only_neighbour(test_client, isolation_data, private_only_neighbour):
    """The pack is built for pasting into tickets — it must carry only visible context."""
    url = f"/intel/entities/{isolation_data['entity'].id}/ioc-pack"

    async def indicator_values(email):
        await _login(test_client, email)
        resp = await test_client.get(url)
        assert resp.status_code == 200, resp.text
        return {i["value"] for i in resp.json()["indicators"]}

    assert private_only_neighbour.value not in await indicator_values(isolation_data["other"].email), "IOC pack leaked a private-job neighbour"
    assert private_only_neighbour.value in await indicator_values(isolation_data["owner"].email), "owner should still see their own private-job neighbour"


async def test_entity_stix_export_sightings_exclude_private_jobs(test_client, isolation_data, private_only_neighbour):
    """One sighting is emitted per visible entity/job link, so the count is the assertion.

    The shared entity sits in both jobs and the neighbour only in the private one, so a
    non-owner must see strictly fewer sightings — and no indicator for the neighbour.
    """
    url = f"/intel/entities/{isolation_data['entity'].id}/stix"

    def summarise(payload):
        objs = payload["objects"]
        return (
            sum(1 for o in objs if o.get("type") == "sighting"),
            {o.get("name") for o in objs if o.get("type") == "indicator"},
        )

    await _login(test_client, isolation_data["other"].email)
    other_sightings, other_names = summarise((await test_client.get(url)).json())

    await _login(test_client, isolation_data["owner"].email)
    owner_sightings, owner_names = summarise((await test_client.get(url)).json())

    assert other_sightings == 1, "a sighting exposed the private job's timestamps"
    assert owner_sightings == 2
    assert private_only_neighbour.value not in other_names
    assert private_only_neighbour.value in owner_names


# ── Case exports carry a real, visibility-scoped severity ────────────────────


@pytest.fixture()
async def case_with_both_jobs(test_client, async_db, isolation_data):
    """A shared case owned by `owner`, holding the entity and both jobs.

    Also links the entity to every seeded Finding: `_entity_severity_map` resolves severity
    through `FindingEntityLink`, which the base fixture does not create.
    """
    from app.models import CaseEntityLink, FindingEntityLink, InvestigationCase

    case = InvestigationCase(name="Sev Case", created_by_user_id=isolation_data["owner"].id, is_shared=True)
    async_db.add(case)
    await async_db.flush()
    async_db.add(CaseEntityLink(case_id=case.id, entity_id=isolation_data["entity"].id))
    async_db.add_all(
        [
            CaseJobLink(case_id=case.id, job_id=isolation_data["job_pub"].id),
            CaseJobLink(case_id=case.id, job_id=isolation_data["job_priv"].id),
        ]
    )
    for f in (await async_db.execute(select(Finding))).scalars().all():
        async_db.add(FindingEntityLink(finding_id=f.id, entity_id=isolation_data["entity"].id))
    await async_db.commit()
    await async_db.refresh(case)
    return case


async def test_case_misp_export_reports_a_real_threat_level(test_client, isolation_data, case_with_both_jobs):
    """`threat_level_for_entities` was called without a severity map, so every export
    said threat_level_id "4" (undefined) no matter how bad the findings were."""
    await _login(test_client, isolation_data["owner"].email)
    resp = await test_client.get(f"/intel/cases/{case_with_both_jobs.id}/misp")
    assert resp.status_code == 200, resp.text

    # The seeded findings are HIGH → threat level 2 ("medium" in MISP's scale is 3,
    # high is 2). Anything but "4" proves the map is threaded through.
    assert resp.json()["Event"]["threat_level_id"] != "4", "MISP export still reports an undefined threat level"


async def test_case_ioc_pack_severity_ignores_invisible_jobs(test_client, async_db, isolation_data, case_with_both_jobs):
    """The severity shown must come only from findings the viewer could open."""
    from app.models import Finding, Severity, TaskResult

    # Make the PRIVATE job's finding the worst one; the public job stays HIGH.
    priv_tr = (await async_db.execute(select(TaskResult).where(TaskResult.job_id == isolation_data["job_priv"].id))).scalars().first()
    crit = (await async_db.execute(select(Finding).where(Finding.task_result_id == priv_tr.id))).scalars().first()
    crit.severity = Severity.CRITICAL
    await async_db.commit()

    url = f"/intel/cases/{case_with_both_jobs.id}/ioc-pack"

    await _login(test_client, isolation_data["other"].email)
    other_sev = {i["value"]: i.get("severity") for i in (await test_client.get(url)).json()["indicators"]}

    await _login(test_client, isolation_data["owner"].email)
    owner_sev = {i["value"]: i.get("severity") for i in (await test_client.get(url)).json()["indicators"]}

    value = isolation_data["entity"].value
    assert owner_sev[value] == "critical", owner_sev
    assert other_sev[value] == "high", f"a non-owner saw a severity derived from a private job: {other_sev}"


# ── Intel dashboard job filter (member-gated) ────────────────────────────────
#
# `?job=` is the only dashboard filter that names another user's submission. Every other
# one is a property of the entity itself, which is a global observable. Left unchecked it
# would be an enumeration primitive: walk the id space, and any job whose filter "works"
# is a job that exists, with its whole entity set rendered. `apply_entity_filters` is pure
# and has no user, so the check can only live in the route.


@pytest.fixture()
async def public_only_entity(async_db, isolation_data):
    """An entity in the *public* job only — the discriminator these tests turn on.

    The dashboard lists every entity globally and always has, so "is this value in the
    response" cannot distinguish a refused filter from an applied one. Whether a
    public-only entity survives can: if the job filter really applied, it is gone.
    """
    e = Entity(value="10.7.7.7", entity_type="ip_address", job_count=1)
    async_db.add(e)
    await async_db.flush()
    async_db.add(EntityJobLink(entity_id=e.id, job_id=isolation_data["job_pub"].id, occurrence_count=1))
    await async_db.commit()
    await async_db.refresh(e)
    return e


async def test_dashboard_job_filter_is_ignored_for_a_job_the_member_cannot_see(test_client, isolation_data, private_only_neighbour, public_only_entity):
    """The filter is dropped, not applied — so the response never reveals the job's members.

    The entity values themselves are not the secret (the unfiltered dashboard lists them
    globally). The secret is *which entities belong to that job*, and refusing to narrow
    is what withholds it.
    """
    await _login(test_client, "other@iso.example.com")
    resp = await test_client.get("/intel/entities-partial", params={"job": isolation_data["job_priv"].id})
    assert resp.status_code == 200
    assert public_only_entity.value in resp.text, "filter must be dropped, not applied, for an invisible job"
    assert "not available" in resp.text


async def test_dashboard_job_filter_applies_for_the_owner(test_client, isolation_data, private_only_neighbour, public_only_entity):
    """Same request, owner: the filter really narrows to the private job's entities."""
    await _login(test_client, "owner@iso.example.com")
    resp = await test_client.get("/intel/entities-partial", params={"job": isolation_data["job_priv"].id})
    assert resp.status_code == 200
    assert private_only_neighbour.value in resp.text
    assert public_only_entity.value not in resp.text, "the owner's job filter did not narrow"


async def test_dashboard_job_filter_works_for_a_visible_job(test_client, isolation_data, private_only_neighbour, public_only_entity):
    """The public job must genuinely filter — otherwise the tests above pass vacuously."""
    await _login(test_client, "other@iso.example.com")
    resp = await test_client.get("/intel/entities-partial", params={"job": isolation_data["job_pub"].id})
    assert resp.status_code == 200
    assert public_only_entity.value in resp.text
    assert private_only_neighbour.value not in resp.text


async def test_dashboard_job_filter_on_invisible_job_does_not_confirm_existence(test_client, isolation_data):
    """A refused filter and a nonexistent id must be indistinguishable.

    Both drop the filter and render the unfiltered table with the same notice, so probing
    ids reveals nothing about which jobs exist.
    """
    await _login(test_client, "other@iso.example.com")
    refused = await test_client.get("/intel/entities-partial", params={"job": isolation_data["job_priv"].id})
    missing = await test_client.get("/intel/entities-partial", params={"job": 99999})
    assert refused.status_code == missing.status_code == 200
    assert "not available" in refused.text
    assert "not available" in missing.text


async def test_dashboard_page_does_not_echo_an_invisible_job_id(test_client, isolation_data):
    """The chip is server-rendered, so an unchecked id would come straight back as HTML."""
    await _login(test_client, "other@iso.example.com")
    resp = await test_client.get("/intel", params={"job": isolation_data["job_priv"].id})
    assert resp.status_code == 200
    assert PRIVATE_FILENAME not in resp.text
    assert "jobId: 0" in resp.text, "an invisible job id must not reach the Alpine root"
