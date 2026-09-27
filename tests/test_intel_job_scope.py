"""`?job=N` narrows the whole entity page, and cannot be used to probe jobs.

The entity page answers a global question — everything ever seen about this entity. An
incident almost always asks a narrower one, so `?job=` scopes the tabbed half of the page
to a single job.

Two properties are worth a test each.

**The badge and its pane agree.** The tab badges are computed in `entity_detail`, the rows
in the partials. If only one of them learns about the scope you get a Findings tab reading
"12" over a list of three, which is exactly the class of small lie the badge counts were
introduced to remove. `_entity_findings_count_stmt` is shared by both for that reason, and
`test_the_badge_agrees_with_the_pane` is what keeps it shared.

**The filter is not an oracle.** Every other filter on this page is a property of the
entity, which is a global observable. A job id is a reference to someone else's
submission, so an unchecked `?job=` would let any member enumerate a private job's
findings one id at a time. Three distinct failures — no such job, a private job, a visible
job unrelated to this entity — must be indistinguishable in the response.
"""

from __future__ import annotations

import re

import pytest

TABS_WITH_A_JOB_SCOPE = ("findings", "relationships", "mitre", "graph")


async def _seed(async_db, *, owner_id=None, private=False):
    """Two jobs over one shared entity, plus a second entity only job A saw.

    Returns (entity, other_entity, job_a, job_b).
    """
    from app.models import (
        AnalysisJob,
        Entity,
        EntityJobLink,
        EntityRelationship,
        Finding,
        FindingEntityLink,
        JobStatus,
        LogFile,
        Severity,
        TaskResult,
        TaskStatus,
        WorkflowDef,
    )

    entity = Entity(value="powershell.exe", entity_type="executable", job_count=2)
    other = Entity(value="WS01", entity_type="computer", job_count=1)
    wf = WorkflowDef(name="wf")
    async_db.add_all([entity, other, wf])
    await async_db.commit()

    jobs = []
    for idx, tag in enumerate(("a", "b")):
        lf = LogFile(original_filename=f"{tag}.evtx", stored_filename=f"{tag}.evtx", sha256=tag * 64, size_bytes=1)
        async_db.add(lf)
        await async_db.commit()
        job = AnalysisJob(
            submitted_filename=lf.original_filename,
            effective_log_type=lf.log_type,
            file_id=lf.id,
            workflow_id=wf.id,
            status=JobStatus.COMPLETED,
            is_private=private and idx == 1,
            submitted_by_user_id=owner_id if (private and idx == 1) else None,
        )
        async_db.add(job)
        await async_db.commit()
        jobs.append(job)

    job_a, job_b = jobs

    # The shared entity is in both jobs; `other` only in job A.
    async_db.add_all(
        [
            EntityJobLink(entity_id=entity.id, job_id=job_a.id, occurrence_count=5),
            EntityJobLink(entity_id=entity.id, job_id=job_b.id, occurrence_count=1),
            EntityJobLink(entity_id=other.id, job_id=job_a.id, occurrence_count=3),
        ]
    )
    # A typed edge whose other endpoint lives only in job A.
    async_db.add(EntityRelationship(source_entity_id=entity.id, target_entity_id=other.id, relationship_type="runs_on", occurrence_count=2))
    await async_db.commit()

    # One finding per job, each tagged with a distinct technique.
    for job, technique, rule in ((job_a, "attack.t1059.001", "Rule in job A"), (job_b, "attack.t1003", "Rule in job B")):
        tr = TaskResult(job_id=job.id, tool_name="zircolite", status=TaskStatus.COMPLETED, findings_count=1)
        async_db.add(tr)
        await async_db.commit()
        f = Finding(
            task_result_id=tr.id,
            rule_id=f"r-{job.id}",
            rule_name=rule,
            severity=Severity.HIGH,
            count=1,
            tags=f'["{technique}"]',
        )
        async_db.add(f)
        await async_db.commit()
        async_db.add(FindingEntityLink(finding_id=f.id, entity_id=entity.id))
    await async_db.commit()

    return entity, other, job_a, job_b


# ─── The scope narrows each tab ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_findings_narrow_to_the_selected_job(member_client, async_db):
    entity, _other, job_a, job_b = await _seed(async_db)

    unscoped = await member_client.get(f"/intel/entities/{entity.id}/findings-partial")
    assert "Rule in job A" in unscoped.text
    assert "Rule in job B" in unscoped.text

    scoped = await member_client.get(f"/intel/entities/{entity.id}/findings-partial?job={job_a.id}")
    assert "Rule in job A" in scoped.text
    assert "Rule in job B" not in scoped.text

    scoped_b = await member_client.get(f"/intel/entities/{entity.id}/findings-partial?job={job_b.id}")
    assert "Rule in job B" in scoped_b.text
    assert "Rule in job A" not in scoped_b.text


@pytest.mark.asyncio
async def test_mitre_narrows_to_the_selected_job(member_client, async_db):
    """Added only when a visibility scope needs it, the TaskResult join would make a job
    scope silently do nothing for admins. Both viewer kinds are covered here."""
    entity, _other, job_a, _job_b = await _seed(async_db)

    unscoped = await member_client.get(f"/intel/entities/{entity.id}/mitre-partial")
    assert "T1059.001" in unscoped.text
    assert "T1003" in unscoped.text

    scoped = await member_client.get(f"/intel/entities/{entity.id}/mitre-partial?job={job_a.id}")
    assert "T1059.001" in scoped.text
    assert "T1003" not in scoped.text


@pytest.mark.asyncio
async def test_mitre_job_scope_also_applies_for_an_admin(admin_client, async_db):
    """Admins take the `job_vis is None` branch, which is where the join could vanish."""
    entity, _other, job_a, _job_b = await _seed(async_db)

    scoped = await admin_client.get(f"/intel/entities/{entity.id}/mitre-partial?job={job_a.id}")
    assert "T1059.001" in scoped.text
    assert "T1003" not in scoped.text


@pytest.mark.asyncio
async def test_the_mitre_layer_download_carries_the_scope(member_client, async_db):
    """A downloaded layer outlives the page it came from, so the scope goes in the file."""
    entity, _other, job_a, _job_b = await _seed(async_db)

    layer = (await member_client.get(f"/intel/entities/{entity.id}/mitre-layer?job={job_a.id}")).json()
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1059.001"]
    assert f"job #{job_a.id}" in layer["name"]
    assert f"job #{job_a.id}" in layer["description"]


@pytest.mark.asyncio
async def test_relationships_narrow_by_co_occurrence(member_client, async_db):
    """`EntityRelationship` has no job column; the other endpoint's presence is the filter."""
    entity, other, job_a, job_b = await _seed(async_db)

    scoped_a = await member_client.get(f"/intel/entities/{entity.id}/relationships-partial?job={job_a.id}")
    assert other.value in scoped_a.text

    # `other` never appears in job B, so the edge drops out there.
    scoped_b = await member_client.get(f"/intel/entities/{entity.id}/relationships-partial?job={job_b.id}")
    assert other.value not in scoped_b.text
    assert "No typed relationships" in scoped_b.text


# ─── Badge honesty ───────────────────────────────────────────────────────────────


def _badge(page_html: str, label: str) -> int | None:
    """Pull the badge integer rendered beside a tab label."""
    m = re.search(rf">\s*{label}\s*<span[^>]*>(\d+)</span>", page_html)
    return int(m.group(1)) if m else None


def _row_count(partial_html: str) -> int:
    m = re.search(r"(\d+) finding", partial_html)
    return int(m.group(1)) if m else 0


@pytest.mark.asyncio
async def test_the_badge_agrees_with_the_pane(member_client, async_db):
    entity, _other, job_a, _job_b = await _seed(async_db)

    for job in (0, job_a.id):
        qs = f"?job={job}" if job else ""
        page = await member_client.get(f"/intel/entities/{entity.id}{qs}")
        pane = await member_client.get(f"/intel/entities/{entity.id}/findings-partial{qs}")
        assert _badge(page.text, "Findings") == _row_count(pane.text), f"badge and pane disagree for job={job}"

    # And the scope actually changed the number, so the assertion above is not vacuous.
    unscoped_page = await member_client.get(f"/intel/entities/{entity.id}")
    scoped_page = await member_client.get(f"/intel/entities/{entity.id}?job={job_a.id}")
    assert _badge(unscoped_page.text, "Findings") == 2
    assert _badge(scoped_page.text, "Findings") == 1


@pytest.mark.asyncio
async def test_every_lazy_pane_carries_the_scope(member_client, async_db):
    """A region that forgets `?job=` renders perfectly and shows the wrong data."""
    entity, _other, job_a, _job_b = await _seed(async_db)

    body = (await member_client.get(f"/intel/entities/{entity.id}?job={job_a.id}")).text
    for tab in TABS_WITH_A_JOB_SCOPE:
        assert f"/intel/entities/{entity.id}/{tab}-partial?job={job_a.id}" in body, f"the {tab} pane dropped the job scope"


@pytest.mark.asyncio
async def test_the_picker_offers_every_visible_job_and_marks_the_active_one(member_client, async_db):
    entity, _other, job_a, job_b = await _seed(async_db)

    body = (await member_client.get(f"/intel/entities/{entity.id}?job={job_b.id}")).text
    assert f'<option value="{job_a.id}"' in body
    assert f'<option value="{job_b.id}" selected' in body
    assert "a.evtx" in body and "b.evtx" in body


# ─── The filter is not an oracle ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_unknown_job_is_dropped_not_404ed(member_client, async_db):
    entity, _other, _job_a, _job_b = await _seed(async_db)

    resp = await member_client.get(f"/intel/entities/{entity.id}?job=999999")
    assert resp.status_code == 200
    assert "That job is not available" in resp.text


@pytest.mark.asyncio
async def test_a_private_job_is_indistinguishable_from_a_nonexistent_one(member_client, admin_user, async_db):
    """The whole point: a member must not learn which private job ids exist."""
    entity, _other, _job_a, job_b = await _seed(async_db, owner_id=admin_user.id, private=True)

    private = await member_client.get(f"/intel/entities/{entity.id}?job={job_b.id}")
    absent = await member_client.get(f"/intel/entities/{entity.id}?job=999999")

    assert private.status_code == absent.status_code == 200
    # Neither response echoes the probed id anywhere, so the two are byte-identical.
    assert private.text == absent.text


@pytest.mark.asyncio
async def test_a_visible_job_unrelated_to_this_entity_is_dropped_the_same_way(member_client, async_db):
    """Membership in `all_job_ids` is entity-scoped as well as visibility-scoped."""
    from sqlalchemy import select

    from app.models import AnalysisJob, JobStatus, LogFile, WorkflowDef

    entity, _other, _job_a, _job_b = await _seed(async_db)

    lf = LogFile(original_filename="unrelated.evtx", stored_filename="u.evtx", sha256="d" * 64, size_bytes=1)
    wf = (await async_db.execute(select(WorkflowDef))).scalars().first()
    async_db.add(lf)
    await async_db.commit()
    stranger = AnalysisJob(submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED)
    async_db.add(stranger)
    await async_db.commit()

    resp = await member_client.get(f"/intel/entities/{entity.id}?job={stranger.id}")
    assert resp.status_code == 200
    assert "That job is not available" in resp.text
    absent = await member_client.get(f"/intel/entities/{entity.id}?job=999999")
    assert resp.text == absent.text


@pytest.mark.asyncio
@pytest.mark.parametrize("tab", TABS_WITH_A_JOB_SCOPE)
async def test_each_partial_rechecks_the_scope_itself(member_client, admin_user, async_db, tab):
    """The partials are directly reachable, so the page-level check is not enough."""
    entity, _other, _job_a, job_b = await _seed(async_db, owner_id=admin_user.id, private=True)

    probed = await member_client.get(f"/intel/entities/{entity.id}/{tab}-partial?job={job_b.id}")
    absent = await member_client.get(f"/intel/entities/{entity.id}/{tab}-partial?job=999999")
    assert probed.status_code == absent.status_code == 200
    assert probed.text == absent.text


# ─── The graph gate ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_graph_tab_refuses_to_draw_until_a_job_is_picked(member_client, async_db):
    """No `graphComponent` at all without a job — so no WebGL context and no export URL
    for a picture nobody can see."""
    entity, _other, job_a, _job_b = await _seed(async_db)

    empty = await member_client.get(f"/intel/entities/{entity.id}/graph-partial")
    assert empty.status_code == 200
    assert "graphComponent(" not in empty.text
    assert "Pick a job to draw the graph." in empty.text

    drawn = await member_client.get(f"/intel/entities/{entity.id}/graph-partial?job={job_a.id}")
    assert "graphComponent(" in drawn.text
    assert f'"jobId": {job_a.id}' in drawn.text or f"&#34;jobId&#34;: {job_a.id}" in drawn.text


@pytest.mark.asyncio
async def test_graph_json_empties_rather_than_widening_on_a_bad_job(member_client, admin_user, async_db):
    """The opposite failure mode to the dashboard's `?job=`.

    There, dropping an unusable filter widens to a table that is still correct. Here it
    would render the full unscoped graph, contradicting the gate — so an invisible job and
    a nonexistent one both return the same empty payload.
    """
    entity, _other, job_a, job_b = await _seed(async_db, owner_id=admin_user.id, private=True)

    real = (await member_client.get(f"/intel/entities/{entity.id}/graph.json?job={job_a.id}")).json()
    assert real["stats"]["nodes"] >= 1

    private = (await member_client.get(f"/intel/entities/{entity.id}/graph.json?job={job_b.id}")).json()
    absent = (await member_client.get(f"/intel/entities/{entity.id}/graph.json?job=999999")).json()
    assert private == absent
    assert private["stats"]["nodes"] == 0
    assert private["stats"]["total_nodes"] == 0


@pytest.mark.asyncio
async def test_the_graphml_export_follows_the_same_rule(member_client, admin_user, async_db):
    entity, _other, _job_a, job_b = await _seed(async_db, owner_id=admin_user.id, private=True)

    private = await member_client.get(f"/intel/entities/{entity.id}/graph.graphml?job={job_b.id}")
    absent = await member_client.get(f"/intel/entities/{entity.id}/graph.graphml?job=999999")
    assert private.status_code == absent.status_code == 200
    assert private.text == absent.text
    assert "<node" not in private.text


@pytest.mark.asyncio
async def test_the_empty_payload_carries_every_key_the_client_decoder_reads(member_client, async_db):
    """A stats block missing a key is an `undefined` read in a reducer — a blank canvas
    with no error, which is worse than an error."""
    from app.intel.graph import _stats

    entity, _other, _job_a, _job_b = await _seed(async_db)
    payload = (await member_client.get(f"/intel/entities/{entity.id}/graph.json?job=999999")).json()
    assert set(payload["stats"]) == set(_stats(0, 0, total_nodes=0, total_edges=0))


# ─── Auto-scope when there is only one job ───────────────────────────────────────
#
# An entity seen in exactly one job must not make you choose that job from a list of one
# before the Graph tab draws anything, so the page redirects to that scope. The guard is
# `?job=` being *absent* rather than `job` being falsy,
# which is what keeps the oracle tests above reachable: every one of them passes `?job=`
# explicitly, so none of them can be answered by a redirect instead.


@pytest.mark.asyncio
async def test_a_single_job_entity_redirects_to_its_only_scope(member_client, async_db):
    _entity, other, job_a, _job_b = await _seed(async_db)

    resp = await member_client.get(f"/intel/entities/{other.id}", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/intel/entities/{other.id}?job={job_a.id}"


@pytest.mark.asyncio
async def test_a_multi_job_entity_is_left_alone(member_client, async_db):
    entity, _other, _job_a, _job_b = await _seed(async_db)

    resp = await member_client.get(f"/intel/entities/{entity.id}", follow_redirects=False)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_job_zero_is_an_explicit_escape_hatch(member_client, async_db):
    """`?job=0` means "show me everything" and must never bounce back to the scope."""
    _entity, other, _job_a, _job_b = await _seed(async_db)

    resp = await member_client.get(f"/intel/entities/{other.id}?job=0", follow_redirects=False)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_a_dropped_job_keeps_its_message_instead_of_redirecting(member_client, async_db):
    """The redirect must not fire out from under `JOB_SCOPE_DROPPED` — otherwise a bad
    `?job=` on a one-job entity silently succeeds and the viewer is never told."""
    from app.routers.intel import JOB_SCOPE_DROPPED

    _entity, other, _job_a, _job_b = await _seed(async_db)

    resp = await member_client.get(f"/intel/entities/{other.id}?job=999999", follow_redirects=False)
    assert resp.status_code == 200
    assert JOB_SCOPE_DROPPED in resp.text


@pytest.mark.asyncio
async def test_the_dead_picker_is_hidden_when_there_is_only_one_job(member_client, async_db):
    """ "All jobs (1)" and Clear both navigated to a URL that redirects straight back."""
    _entity, other, job_a, _job_b = await _seed(async_db)

    body = (await member_client.get(f"/intel/entities/{other.id}?job={job_a.id}")).text
    assert "All jobs (1)" not in body
    assert ">Clear</a>" not in body
    assert f"/jobs/{job_a.id}" in body  # the "Open job" link survives
