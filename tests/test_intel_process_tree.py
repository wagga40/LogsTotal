"""Process trees anchored on an entity, reachable from Intel and Cases.

The process tree is the best artifact for "how did this actually run", so beyond the job
page it is a tab on the entity and on the case, pruned to the chains that mention one
observable.

The pruning is server-side, and that is the load-bearing decision: `build_process_forest`
truncates at `DEFAULT_MAX_NODES` **during the parse, before relevance is known**, so on a
busy job the entity's own processes may simply not be among the first 500 a client-side
filter would ever see. `test_pruning_finds_a_match_the_node_cap_would_have_hidden` is that
argument as a test.

The rest is authorization. Both routes are new rather than an `?entity_id=` on
`/jobs/{id}/process-tree`, because that one is anonymous-viewable for a public job and
would become an entity-existence oracle for anyone at all.
"""

from __future__ import annotations

import pytest

from app.intel.lineage import PROCESS_TREE_ENTITY_TYPES, build_process_forest, node_matches_entity, prune_to_entity


def _sysmon(pid, ppid, image, *, guid=None, pguid=None, user="CORP\\alice", computer="WS01", cmdline="", time="2026-01-01 10:00:00.000", hashes=""):
    ev = {
        "EventID": 1,
        "ProcessId": str(pid),
        "ParentProcessId": str(ppid),
        "Image": image,
        "User": user,
        "Computer": computer,
        "CommandLine": cmdline or image,
        "UtcTime": time,
    }
    if guid:
        ev["ProcessGuid"] = guid
    if pguid:
        ev["ParentProcessGuid"] = pguid
    if hashes:
        ev["Hashes"] = hashes
    return ev


# ─── Tier 1: the pure half ───────────────────────────────────────────────────────


class TestHashes:
    def test_sysmon_composite_hashes_land_on_the_node_uppercased(self):
        forest = build_process_forest([_sysmon(100, 4, r"C:\Windows\System32\cmd.exe", hashes="MD5=" + "a" * 32 + ",SHA256=" + "d" * 64)])
        node = forest["roots"][0]
        assert node["hashes"] == ["A" * 32, "D" * 64]

    def test_a_value_that_is_not_a_hash_length_is_rejected(self):
        """`_extract_hashes` validates the digest, so `MD5=abc123` never becomes an IOC."""
        forest = build_process_forest([_sysmon(100, 4, r"C:\Windows\System32\cmd.exe", hashes="MD5=abc123")])
        assert forest["roots"][0]["hashes"] == []

    def test_events_without_hashes_get_an_empty_list_not_a_missing_key(self):
        forest = build_process_forest([_sysmon(100, 4, r"C:\Windows\System32\cmd.exe")])
        assert forest["roots"][0]["hashes"] == []


class TestNodeMatching:
    def test_executable_is_exact_on_the_basename(self):
        """Substring would make `ps.exe` match `wsmprovhost.exe`."""
        node = {"image": "powershell.exe"}
        assert node_matches_entity(node, "executable", "powershell.exe")
        assert node_matches_entity(node, "executable", r"C:\Windows\powershell.exe"), "a full path narrows to its basename"
        assert not node_matches_entity(node, "executable", "shell.exe")

    def test_computer_and_user_are_case_insensitive(self):
        node = {"computer": "WS01", "user": "CORP\\Alice"}
        assert node_matches_entity(node, "computer", "ws01")
        assert node_matches_entity(node, "user", "alice"), "the node side carries a DOMAIN\\ prefix the entity does not"
        assert node_matches_entity(node, "user", "CORP\\ALICE")
        assert not node_matches_entity(node, "user", "bob")

    def test_cmdline_file_is_a_substring_because_that_is_the_relationship(self):
        node = {"cmdline": r"powershell.exe -File C:\temp\Evil.ps1"}
        assert node_matches_entity(node, "cmdline_file", "evil.ps1")
        assert not node_matches_entity(node, "cmdline_file", "good.ps1")

    def test_hash_membership_is_case_insensitive(self):
        node = {"hashes": ["D" * 64]}
        assert node_matches_entity(node, "hash", "d" * 64)
        assert not node_matches_entity(node, "hash", "e" * 64)

    def test_a_node_from_before_the_hashes_field_existed_does_not_explode(self):
        """A cached v1 forest is still served for up to the TTL after a deploy."""
        assert node_matches_entity({"image": "x.exe"}, "hash", "d" * 64) is False

    def test_ineligible_types_never_match(self):
        node = {"image": "x.exe", "cmdline": "x.exe 10.0.0.1 evil.com", "computer": "WS01"}
        for etype in ("ip_address", "domain", "service", "task"):
            assert not node_matches_entity(node, etype, "10.0.0.1")

    def test_the_eligible_set_is_exactly_the_types_with_a_node_field(self):
        assert {"computer", "executable", "cmdline_file", "user", "hash"} == PROCESS_TREE_ENTITY_TYPES

    def test_a_renamed_binary_anchors_on_its_original_filename(self):
        """The case a process tree is most worth opening for, and it never matched.

        Sysmon EID 1 emits both `Image` (what it was launched as) and `OriginalFileName`
        (what the vendor compiled it as). The analytics extractor reads both keys, so the
        entity is `mimikatz.exe` while the node's image was only ever `svchost.exe`.
        """
        node = {"image": "svchost.exe", "image_alts": ["mimikatz.exe"]}
        assert node_matches_entity(node, "executable", "mimikatz.exe")
        assert node_matches_entity(node, "executable", r"C:\tools\mimikatz.exe")
        assert node_matches_entity(node, "executable", "svchost.exe"), "the launched name still anchors"
        assert not node_matches_entity(node, "executable", "kaz.exe"), "still exact, not substring"

    def test_a_node_from_before_image_alts_existed_does_not_explode(self):
        """Same defence as `hashes`: a cached v3 forest outlives the deploy by a TTL."""
        assert node_matches_entity({"image": "x.exe"}, "executable", "x.exe")
        assert node_matches_entity({"image": "x.exe"}, "executable", "y.exe") is False

    def test_computer_matches_across_the_dns_suffix(self):
        """An EVTX `Computer` and an auditd `node` describe the same host in one case."""
        assert node_matches_entity({"computer": "WS01.corp.local"}, "computer", "ws01")
        assert node_matches_entity({"computer": "ws01"}, "computer", "WS01.corp.local")
        assert not node_matches_entity({"computer": "WS01.corp.local"}, "computer", "ws02")

    def test_an_ip_hostname_keeps_every_octet(self):
        """`10.0.0.5` must not degrade to `10` and match every 10.x host in the job."""
        assert node_matches_entity({"computer": "10.0.0.5"}, "computer", "10.0.0.5")
        assert not node_matches_entity({"computer": "10.0.0.5"}, "computer", "10.0.0.9")


class TestEntityValuesRoundTripToNodes:
    """The seam the rest of this class could not see.

    Every other matching test asserts against a hand-written node dict, so it pins the
    matcher against itself. The failure that shipped was upstream of the matcher: the
    entity extractor and the lineage parser read *different key sets* out of the same
    event, so a perfectly correct matcher was comparing a value that existed against a
    field that was never populated. This drives both halves from one fixture event.
    """

    @staticmethod
    def _entities(event, monkeypatch):
        """The real fold, over the real `config/analytics_fields.yaml`.

        The extraction is inlined in `_compute_analytics_data`, which drives it by reading
        the job's raw output off disk. Rather than restructure that (or write fixture files
        for a Tier-1 test), the disk read is replaced with a feed of one event — everything
        downstream of it, including the field-dispatch table, is the shipping code.
        """
        from app import analytics

        def _feed(_job_id, _rule_tactic, _technique_tactic, *, markers=None, rule_meta=None, consumer=None, job_dir=None):
            if consumer is not None:
                consumer(event)
            return {}, []

        monkeypatch.setattr(analytics, "extract_all_from_raw_output", _feed)

        class _StubJob:
            id = 1
            task_results: list = []

        return analytics._compute_analytics_data(_StubJob())

    @pytest.mark.parametrize(
        ("entity_key", "entity_type"),
        [("executables", "executable"), ("users", "user"), ("computers", "computer"), ("hashes", "hash")],
    )
    def test_every_extracted_entity_of_an_eligible_type_anchors_its_own_event(self, entity_key, entity_type, monkeypatch):
        event = _sysmon(
            100,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            user="CORP\\alice",
            computer="WS01",
            hashes="MD5=" + "a" * 32 + ",SHA256=" + "d" * 64,
        )
        forest = build_process_forest([event])
        node = forest["roots"][0]

        values = self._entities(event, monkeypatch)[entity_key]
        assert values, f"the extractor found no {entity_key} in this event"
        # Not "at least one matches" — every value the extractor derived from *this* event
        # must anchor in the node built from *the same* event, or the two halves disagree.
        for value in values:
            assert node_matches_entity(node, entity_type, value), f"{entity_type} {value!r} does not anchor its own event"

    def test_a_renamed_binary_round_trips(self, monkeypatch):
        """What this class exists for.

        The extractor turns `OriginalFileName` into an `executable` entity; without
        `image_alts` the node would know only the `Image` basename, so the entity could never
        anchor the very event it came from.
        """
        event = _sysmon(100, 4, r"C:\temp\svchost.exe")
        event["OriginalFileName"] = "mimikatz.exe"

        node = build_process_forest([event])["roots"][0]
        executables = self._entities(event, monkeypatch)["executables"]

        assert "mimikatz.exe" in executables, "the extractor reads OriginalFileName"
        assert "mimikatz.exe" not in (node["image"],), "the node's own image is what launched"
        for value in executables:
            assert node_matches_entity(node, "executable", value), f"{value!r} does not anchor its own event"


class TestPruning:
    @staticmethod
    def _chain():
        """services.exe -> svchost.exe -> powershell.exe -> whoami.exe, plus a sibling."""
        return build_process_forest(
            [
                _sysmon(100, 4, r"C:\Windows\System32\services.exe", guid="g1", time="2026-01-01 10:00:00.000"),
                _sysmon(200, 100, r"C:\Windows\System32\svchost.exe", guid="g2", pguid="g1", time="2026-01-01 10:00:01.000"),
                _sysmon(300, 200, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", guid="g3", pguid="g2", time="2026-01-01 10:00:02.000"),
                _sysmon(400, 300, r"C:\Windows\System32\whoami.exe", guid="g4", pguid="g3", time="2026-01-01 10:00:03.000"),
                _sysmon(500, 100, r"C:\Windows\System32\spoolsv.exe", guid="g5", pguid="g1", time="2026-01-01 10:00:04.000"),
            ]
        )

    @staticmethod
    def _flatten(nodes):
        out = []
        for n in nodes:
            out.append(n)
            out.extend(TestPruning._flatten(n["children"]))
        return out

    def test_ancestors_are_kept_because_they_are_the_whole_point(self):
        pruned = prune_to_entity(self._chain(), "executable", "powershell.exe")
        images = [n["image"] for n in self._flatten(pruned["roots"])]
        assert "services.exe" in images and "svchost.exe" in images, "a matched process with no story is not a process tree"

    def test_the_subtree_below_a_match_is_kept_because_it_is_the_kill_chain(self):
        pruned = prune_to_entity(self._chain(), "executable", "powershell.exe")
        assert "whoami.exe" in [n["image"] for n in self._flatten(pruned["roots"])]

    def test_unrelated_branches_are_dropped(self):
        pruned = prune_to_entity(self._chain(), "executable", "powershell.exe")
        assert "spoolsv.exe" not in [n["image"] for n in self._flatten(pruned["roots"])]

    def test_only_the_matches_are_marked(self):
        pruned = prune_to_entity(self._chain(), "executable", "powershell.exe")
        marked = [n["image"] for n in self._flatten(pruned["roots"]) if n.get("match")]
        assert marked == ["powershell.exe"]
        assert pruned["stats"]["matched"] == 1
        assert pruned["stats"]["entity_pruned"] is True

    def test_no_match_yields_an_empty_forest_not_the_whole_tree(self):
        pruned = prune_to_entity(self._chain(), "executable", "nothing-here.exe")
        assert pruned["roots"] == []
        assert pruned["stats"]["matched"] == 0

    def test_the_input_forest_is_not_modified(self):
        """The unfiltered build is cached and pruned repeatedly for different entities."""
        forest = self._chain()
        before = len(self._flatten(forest["roots"]))
        prune_to_entity(forest, "executable", "powershell.exe")
        assert len(self._flatten(forest["roots"])) == before
        assert all("match" not in n for n in self._flatten(forest["roots"]))

    def test_a_computer_anchor_keeps_the_whole_host(self):
        pruned = prune_to_entity(self._chain(), "computer", "ws01")
        assert pruned["stats"]["matched"] == 5

    def test_pruning_finds_a_match_the_node_cap_would_have_hidden(self):
        """The argument for pruning server-side rather than filtering in the browser.

        `build_process_forest` truncates during the parse, so with a small cap the
        interesting process is not in the forest at all — no client filter could reach it.
        Pruning a forest built without that cap does find it.
        """
        noise = [_sysmon(1000 + i, 4, rf"C:\noise\proc{i}.exe", guid=f"n{i}", time=f"2026-01-01 09:00:{i:02d}.000") for i in range(40)]
        needle = _sysmon(9999, 4, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", guid="needle", time="2026-01-01 11:00:00.000")
        events = [*noise, needle]

        capped = build_process_forest(events, max_nodes=10)
        assert "powershell.exe" not in [n["image"] for n in self._flatten(capped["roots"])]

        full = prune_to_entity(build_process_forest(events), "executable", "powershell.exe")
        assert [n["image"] for n in self._flatten(full["roots"])] == ["powershell.exe"]


# ─── Tier 2: the two routes ──────────────────────────────────────────────────────


async def _seed_case_with_job(async_db, *, private=False, owner_id=None):
    """A case holding one job and one eligible entity, plus one ineligible entity."""
    from app.models import (
        AnalysisJob,
        CaseEntityLink,
        CaseJobLink,
        Entity,
        EntityJobLink,
        InvestigationCase,
        JobStatus,
        LogFile,
        WorkflowDef,
    )

    wf = WorkflowDef(name="wf")
    lf = LogFile(original_filename="p.evtx", stored_filename="p.evtx", sha256="f" * 64, size_bytes=1)
    async_db.add_all([wf, lf])
    await async_db.commit()

    job = AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, is_private=private, submitted_by_user_id=owner_id)
    async_db.add(job)
    await async_db.commit()

    exe = Entity(value="powershell.exe", entity_type="executable", job_count=1)
    ip = Entity(value="10.0.0.7", entity_type="ip_address", job_count=1)
    async_db.add_all([exe, ip])
    await async_db.commit()
    async_db.add_all(
        [
            EntityJobLink(entity_id=exe.id, job_id=job.id, occurrence_count=1),
            EntityJobLink(entity_id=ip.id, job_id=job.id, occurrence_count=1),
        ]
    )
    case = InvestigationCase(name="Proc case", status="open", created_by_user_id=owner_id, is_shared=True)
    async_db.add(case)
    await async_db.commit()
    async_db.add_all(
        [
            CaseJobLink(case_id=case.id, job_id=job.id),
            CaseEntityLink(case_id=case.id, entity_id=exe.id),
        ]
    )
    await async_db.commit()
    return {"case": case, "job": job, "exe": exe, "ip": ip}


@pytest.mark.asyncio
async def test_the_entity_tab_exists_only_for_eligible_types(member_client, async_db):
    from app.models import Entity
    from app.routers.intel import _build_entity_tabs

    for etype in ("computer", "executable", "cmdline_file", "user", "hash"):
        tabs = _build_entity_tabs(Entity(value="x", entity_type=etype), 0)
        assert "processes" in [t["key"] for t in tabs], etype
    for etype in ("ip_address", "domain", "service", "task"):
        tabs = _build_entity_tabs(Entity(value="x", entity_type=etype), 0)
        assert "processes" not in [t["key"] for t in tabs], etype


@pytest.mark.asyncio
async def test_the_site_setting_closes_the_side_door(async_db):
    """An admin who turned the job-page panel off must not get it back via Intel."""
    from app.models import Entity
    from app.routers.intel import _build_entity_tabs

    tabs = _build_entity_tabs(Entity(value="x", entity_type="executable"), 0, show_process_tree=False)
    assert "processes" not in [t["key"] for t in tabs]


@pytest.mark.asyncio
async def test_the_entity_route_builds_nothing_without_a_job(member_client, async_db, monkeypatch):
    """No job means no forest — and, crucially, no parse of anything."""
    import app.intel.process_tree as pt_module

    seeded = await _seed_case_with_job(async_db)
    calls: list[int] = []
    monkeypatch.setattr(pt_module, "build_job_forest_sync", lambda job_id, **kw: calls.append(job_id) or {"roots": [], "stats": {}})

    resp = await member_client.get(f"/intel/entities/{seeded['exe'].id}/process-tree-partial")
    assert resp.status_code == 200
    assert "Pick a job" in resp.text
    assert calls == [], "the empty state must not touch the parse path"


@pytest.mark.asyncio
async def test_an_ineligible_entity_has_no_route_either(member_client, async_db):
    """The tab is absent; the route must not be a way around that."""
    seeded = await _seed_case_with_job(async_db)
    resp = await member_client.get(f"/intel/entities/{seeded['ip'].id}/process-tree-partial?job={seeded['job'].id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_the_entity_route_renders_a_pruned_tree(member_client, async_db, monkeypatch):
    import app.intel.process_tree as pt_module

    seeded = await _seed_case_with_job(async_db)
    captured: dict = {}

    def _fake(job_id, *, entity_type="", entity_value=""):
        captured.update(job_id=job_id, entity_type=entity_type, entity_value=entity_value)
        return prune_to_entity(
            build_process_forest([_sysmon(100, 4, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]),
            entity_type,
            entity_value,
        )

    monkeypatch.setattr(pt_module, "build_job_forest_sync", _fake)

    resp = await member_client.get(f"/intel/entities/{seeded['exe'].id}/process-tree-partial?job={seeded['job'].id}")
    assert resp.status_code == 200
    assert "powershell.exe" in resp.text
    # Plain values reached the threadpool, never an ORM instance.
    assert captured == {"job_id": seeded["job"].id, "entity_type": "executable", "entity_value": "powershell.exe"}


@pytest.mark.asyncio
async def test_a_job_not_linked_to_the_entity_is_dropped_to_the_empty_state(member_client, async_db):
    from app.models import AnalysisJob, JobStatus, LogFile

    seeded = await _seed_case_with_job(async_db)
    lf = LogFile(original_filename="other.evtx", stored_filename="o.evtx", sha256="9" * 64, size_bytes=1)
    async_db.add(lf)
    await async_db.commit()
    stranger = AnalysisJob(file_id=lf.id, workflow_id=seeded["job"].workflow_id, status=JobStatus.COMPLETED)
    async_db.add(stranger)
    await async_db.commit()

    resp = await member_client.get(f"/intel/entities/{seeded['exe'].id}/process-tree-partial?job={stranger.id}")
    assert resp.status_code == 200
    assert "Pick a job" in resp.text


@pytest.mark.asyncio
async def test_the_case_route_draws_from_a_job_alone(member_client, admin_user, async_db):
    """A job is enough. The entity anchor is a refinement, not a second gate.

    This case holds exactly one job, so the job half is answered for you and the tree is
    what a bare request renders — no placeholder at all. Asserting on the `Process Tree`
    heading, which only `partials/_process_tree.html` emits: the placeholder branch shares
    the same icon and card chrome, so the discriminator has to come from the tree itself.
    """
    seeded = await _seed_case_with_job(async_db, owner_id=admin_user.id)
    case_id = seeded["case"].id

    bare = await member_client.get(f"/intel/cases/{case_id}/process-tree-partial")
    assert bare.status_code == 200
    assert "Process Tree" in bare.text
    assert "Choose a job to read lineage from" not in bare.text

    job_only = await member_client.get(f"/intel/cases/{case_id}/process-tree-partial?job={seeded['job'].id}")
    assert "Process Tree" in job_only.text
    # Unanchored: no amber scope chip, and the Relationships panel belongs to an anchor.
    assert f"job #{seeded['job'].id} \u00b7" not in job_only.text
    assert "Relationships" not in job_only.text


@pytest.mark.asyncio
async def test_the_anchor_picker_only_offers_entities_the_selected_job_saw(member_client, admin_user, async_db):
    """A case-scoped picker would offer entities that anchor nothing.

    A case's entity set and one job's are different lists: linking a job to a case imports
    its observables only when the adder asked for it, and never past `_BULK_ENTITY_CAP`, so
    a case-scoped list would be neither complete nor relevant.
    """
    from app.models import CaseEntityLink, Entity

    seeded = await _seed_case_with_job(async_db, owner_id=admin_user.id)
    case_id, job_id = seeded["case"].id, seeded["job"].id

    # In the case, absent from the job — the shape a second job's observables leave behind.
    elsewhere = Entity(value="notepad.exe", entity_type="executable", job_count=9)
    async_db.add(elsewhere)
    await async_db.commit()
    async_db.add(CaseEntityLink(case_id=case_id, entity_id=elsewhere.id))
    await async_db.commit()

    unscoped = (await member_client.get(f"/intel/cases/{case_id}/entities.json")).json()
    scoped = (await member_client.get(f"/intel/cases/{case_id}/entities.json?job={job_id}")).json()

    assert "notepad.exe" in [e["value"] for e in unscoped]
    assert "notepad.exe" not in [e["value"] for e in scoped]
    assert "powershell.exe" in [e["value"] for e in scoped]


@pytest.mark.asyncio
async def test_a_one_character_query_answers_when_the_picker_is_job_scoped(member_client, admin_user, async_db):
    """`_PICKER_MIN_CHARS` guards the unscoped walk, not an indexed one-job join.

    Refusing a single character was visible as a dropdown that vanished on the first
    keystroke and returned on the second, which is most of what made the field feel broken.
    """
    seeded = await _seed_case_with_job(async_db, owner_id=admin_user.id)
    case_id, job_id = seeded["case"].id, seeded["job"].id

    scoped = (await member_client.get(f"/intel/cases/{case_id}/entities.json?job={job_id}&q=p")).json()
    assert [e["value"] for e in scoped] == ["powershell.exe"]

    unscoped = (await member_client.get(f"/intel/cases/{case_id}/entities.json?q=p")).json()
    assert unscoped == []


@pytest.mark.asyncio
async def test_an_unusable_job_on_the_picker_is_dropped_not_an_oracle(member_client, admin_user, async_db):
    """Same one-message discipline as every other job scope: drop, do not distinguish.

    Byte equality, so a job that does not exist and a job belonging to some other case
    cannot be told apart from passing nothing at all.
    """
    seeded = await _seed_case_with_job(async_db, owner_id=admin_user.id)
    case_id = seeded["case"].id

    absent = await member_client.get(f"/intel/cases/{case_id}/entities.json?job=999999")
    none_at_all = await member_client.get(f"/intel/cases/{case_id}/entities.json")
    assert absent.status_code == none_at_all.status_code == 200
    assert absent.text == none_at_all.text


@pytest.mark.asyncio
async def test_a_stale_anchor_is_dropped_with_a_note_not_a_blank_pane(member_client, admin_user, async_db):
    """Changing the job carries the old anchor along. That must not empty the tab.

    Distinct from an entity outside the case, which still 404s — this one is in the case, so
    it is a state the analyst produced themselves and is worth explaining.
    """
    from app.models import CaseEntityLink, Entity

    seeded = await _seed_case_with_job(async_db, owner_id=admin_user.id)
    case_id, job_id = seeded["case"].id, seeded["job"].id

    elsewhere = Entity(value="notepad.exe", entity_type="executable", job_count=9)
    async_db.add(elsewhere)
    await async_db.commit()
    async_db.add(CaseEntityLink(case_id=case_id, entity_id=elsewhere.id))
    await async_db.commit()

    resp = await member_client.get(f"/intel/cases/{case_id}/process-tree-partial?job={job_id}&entity_id={elsewhere.id}")
    assert resp.status_code == 200
    assert "the anchor was dropped" in resp.text
    assert "Process Tree" in resp.text


@pytest.mark.asyncio
async def test_a_case_with_several_jobs_still_asks(member_client, admin_user, async_db):
    """Auto-adopting is only defensible when there is nothing to choose between."""
    from app.models import AnalysisJob, CaseJobLink, JobStatus, LogFile

    seeded = await _seed_case_with_job(async_db, owner_id=admin_user.id)
    case_id = seeded["case"].id

    lf = LogFile(original_filename="q.evtx", stored_filename="q.evtx", sha256="e" * 64, size_bytes=1)
    async_db.add(lf)
    await async_db.commit()
    second = AnalysisJob(file_id=lf.id, workflow_id=seeded["job"].workflow_id, status=JobStatus.COMPLETED)
    async_db.add(second)
    await async_db.commit()
    async_db.add(CaseJobLink(case_id=case_id, job_id=second.id))
    await async_db.commit()

    bare = await member_client.get(f"/intel/cases/{case_id}/process-tree-partial")
    assert "Choose a job to read lineage from" in bare.text


@pytest.mark.asyncio
async def test_the_case_route_404s_for_an_entity_outside_the_case(member_client, admin_user, async_db):
    """One message, so a filter value cannot enumerate entities beyond this case."""
    from app.models import Entity

    seeded = await _seed_case_with_job(async_db, owner_id=admin_user.id)
    outsider = Entity(value="stranger.exe", entity_type="executable", job_count=1)
    async_db.add(outsider)
    await async_db.commit()

    resp = await member_client.get(f"/intel/cases/{seeded['case'].id}/process-tree-partial?job={seeded['job'].id}&entity_id={outsider.id}")
    absent = await member_client.get(f"/intel/cases/{seeded['case'].id}/process-tree-partial?job={seeded['job'].id}&entity_id=999999")
    assert resp.status_code == absent.status_code == 404
    assert resp.json() == absent.json()


@pytest.mark.asyncio
async def test_the_case_entity_picker_can_be_narrowed_to_eligible_types(member_client, admin_user, async_db):
    seeded = await _seed_case_with_job(async_db, owner_id=admin_user.id)
    from app.models import CaseEntityLink

    async_db.add(CaseEntityLink(case_id=seeded["case"].id, entity_id=seeded["ip"].id))
    await async_db.commit()

    everything = (await member_client.get(f"/intel/cases/{seeded['case'].id}/entities.json")).json()
    assert {e["entity_type"] for e in everything} == {"executable", "ip_address"}

    narrowed = (await member_client.get(f"/intel/cases/{seeded['case'].id}/entities.json?types=executable,user,hash")).json()
    assert {e["entity_type"] for e in narrowed} == {"executable"}


@pytest.mark.asyncio
async def test_the_job_page_route_still_takes_no_entity(member_client, async_db):
    """It is anonymous-viewable, so accepting one would be an entity oracle for anyone."""
    import inspect

    from app.routers.jobs import job_process_tree

    assert set(inspect.signature(job_process_tree).parameters) == {"job_id", "request", "db", "user"}


def test_pruned_stats_are_all_recounted_not_just_some():
    """Mixing a recounted `processes` with a stale `hits` is worse than either alone.

    The header renders both, so "500 hits / 12 chains" on a pruned tree showing eighty
    nodes is a straight-up wrong number in the UI — found by running the real app.
    """
    noise = [_sysmon(1000 + i, 4, rf"C:\noise\proc{i}.exe", guid=f"n{i}", time=f"2026-01-01 09:00:{i:02d}.000") for i in range(20)]
    needle = _sysmon(9999, 4, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", guid="needle", time="2026-01-01 11:00:00.000")
    forest = build_process_forest([*noise, needle])
    assert forest["stats"]["hits"] == 21

    pruned = prune_to_entity(forest, "executable", "powershell.exe")
    assert pruned["stats"]["processes"] == 1
    assert pruned["stats"]["roots"] == 1
    assert pruned["stats"]["hits"] == 1, "hits must describe the pruned tree, not the source forest"
    assert pruned["stats"]["inferred"] == 0
    assert pruned["stats"]["matched"] == 1


def test_a_synthetic_ancestor_kept_by_the_prune_counts_as_inferred_not_a_hit():
    events = [
        # The child matched a rule; its parent never did, so it is synthesized.
        _sysmon(300, 200, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", guid="g3", pguid="g2"),
    ]
    events[0]["ParentImage"] = r"C:\Windows\System32\svchost.exe"
    pruned = prune_to_entity(build_process_forest(events), "executable", "powershell.exe")
    assert pruned["stats"]["hits"] == 1
    assert pruned["stats"]["inferred"] == 1
    assert pruned["stats"]["processes"] == 2
