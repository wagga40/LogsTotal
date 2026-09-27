"""`fetch_threat_columns` must not paint a node from data the viewer cannot see.

Five columns ride the graph payload — worst finding severity, dominant MITRE tactic,
enrichment verdict, case membership, and the flags derived from them — and three of them
traverse into job- or case-scoped data. Two are leak classes the graph has never had:

  * **severity and tactic** traverse ``FindingEntityLink -> Finding -> TaskResult ->
    AnalysisJob``. Without ``visible_job_filter`` a node renders CRITICAL because of a
    finding inside another analyst's private job — and unlike an edge, a *colour* has no
    obvious provenance for the analyst to question.
  * **case membership** traverses ``CaseEntityLink -> InvestigationCase`` and needs
    ``visible_case_filter``. That discloses both the existence and the membership of an
    unshared case, which no previous graph query could.

Each assertion checks the private contribution is **absent**, not merely different.
"""

from __future__ import annotations

import json
import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.models  # noqa: F401 — populate Base.metadata
from app.database import Base
from app.intel.graph import build_case_graph, build_entity_graph, fetch_threat_columns
from app.models import (
    AnalysisJob,
    CaseEntityLink,
    EnrichmentService,
    Entity,
    EntityEnrichmentResult,
    EntityJobLink,
    Finding,
    FindingEntityLink,
    InvestigationCase,
    JobStatus,
    LogFile,
    Severity,
    TaskResult,
    TaskStatus,
    WorkflowDef,
)
from tests.conftest import decode_graph

OWNER = uuid.uuid4()
STRANGER = uuid.uuid4()

owner = SimpleNamespace(id=OWNER, is_superuser=False)
stranger = SimpleNamespace(id=STRANGER, is_superuser=False)
admin = SimpleNamespace(id=uuid.uuid4(), is_superuser=True)
anonymous = None


@pytest_asyncio.fixture()
async def db():
    engine = create_async_engine("sqlite+aiosqlite://", connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as sess:
        sess.add(LogFile(id=1, original_filename="a.evtx", stored_filename="f1.evtx", sha256="x" * 64, size_bytes=1))
        sess.add(WorkflowDef(id=1, name="wf1"))
        await sess.commit()
        yield sess
    await engine.dispose()


async def _entity(db, eid, value, etype="ip_address"):
    e = Entity(id=eid, value=value, entity_type=etype, job_count=1)
    db.add(e)
    await db.commit()
    return e


async def _job(db, jid, *, private=False, owner_id=None):
    db.add(AnalysisJob(id=jid, file_id=1, workflow_id=1, status=JobStatus.COMPLETED, is_private=private, submitted_by_user_id=owner_id))
    await db.commit()


async def _finding(db, *, fid, job_id, entity_ids, severity=Severity.CRITICAL, tags=None):
    if await db.get(TaskResult, job_id) is None:
        db.add(TaskResult(id=job_id, job_id=job_id, tool_name="zircolite", status=TaskStatus.COMPLETED))
        await db.commit()
    db.add(
        Finding(
            id=fid,
            task_result_id=job_id,
            rule_id=f"r{fid}",
            rule_name=f"rule {fid}",
            severity=severity,
            count=1,
            tags=json.dumps(tags or []),
        )
    )
    await db.commit()
    for eid in entity_ids:
        db.add(FindingEntityLink(finding_id=fid, entity_id=eid))
    await db.commit()


@pytest.mark.asyncio
class TestWorstSeverity:
    async def test_a_private_critical_finding_never_paints_a_node(self, db):
        await _job(db, 1, private=False)
        await _job(db, 2, private=True, owner_id=OWNER)
        e = await _entity(db, 1, "10.0.0.1")
        await _finding(db, fid=1, job_id=1, entity_ids=[e.id], severity=Severity.LOW)
        await _finding(db, fid=2, job_id=2, entity_ids=[e.id], severity=Severity.CRITICAL)

        async def worst(viewer):
            threat, _cases = await fetch_threat_columns(db, [e.id], viewer=viewer)
            row = threat.get(e.id)
            return row.severity if row else None

        # `severity_rank_sql()` ranks CRITICAL as 0 and LOW as 3.
        assert await worst(owner) == 0
        assert await worst(admin) == 0
        assert await worst(stranger) == 3, "a private job's CRITICAL finding leaked into the node colour"
        assert await worst(anonymous) == 3

    async def test_an_entity_seen_only_in_a_private_job_gets_no_severity_at_all(self, db):
        await _job(db, 1, private=True, owner_id=OWNER)
        e = await _entity(db, 1, "10.0.0.1")
        await _finding(db, fid=1, job_id=1, entity_ids=[e.id], severity=Severity.CRITICAL)

        threat, _ = await fetch_threat_columns(db, [e.id], viewer=stranger)
        assert e.id not in threat


@pytest.mark.asyncio
class TestDominantTactic:
    async def test_a_private_finding_does_not_contribute_its_tactic(self, db):
        await _job(db, 1, private=False)
        await _job(db, 2, private=True, owner_id=OWNER)
        e = await _entity(db, 1, "10.0.0.1")
        await _finding(db, fid=1, job_id=1, entity_ids=[e.id], tags=["attack.discovery"])
        # Two private findings, so the private tactic would otherwise outweigh the public one.
        await _finding(db, fid=2, job_id=2, entity_ids=[e.id], tags=["attack.exfiltration"])
        await _finding(db, fid=3, job_id=2, entity_ids=[e.id], tags=["attack.exfiltration", "attack.impact"])

        async def tactic(viewer):
            threat, _ = await fetch_threat_columns(db, [e.id], viewer=viewer)
            return threat[e.id].tactic

        assert await tactic(owner) == "exfiltration"
        assert await tactic(stranger) == "discovery", "a private job's tactic leaked into the node colour"

    async def test_findings_with_no_tactic_tags_leave_the_column_empty(self, db):
        await _job(db, 1)
        e = await _entity(db, 1, "10.0.0.1")
        await _finding(db, fid=1, job_id=1, entity_ids=[e.id], tags=["attack.t1059", "cve-2021-1234"])

        threat, _ = await fetch_threat_columns(db, [e.id], viewer=None)
        assert threat[e.id].tactic is None


@pytest.mark.asyncio
class TestCaseMembership:
    async def test_an_unshared_case_is_invisible_to_a_non_owner(self, db):
        """A leak class the graph has never had — this query is new."""
        e = await _entity(db, 1, "10.0.0.1")
        private_case = InvestigationCase(id=1, name="Private", created_by_user_id=OWNER, is_shared=False)
        shared_case = InvestigationCase(id=2, name="Shared", created_by_user_id=OWNER, is_shared=True)
        db.add_all([private_case, shared_case])
        await db.commit()
        db.add_all(
            [
                CaseEntityLink(case_id=1, entity_id=e.id, added_by_user_id=OWNER),
                CaseEntityLink(case_id=2, entity_id=e.id, added_by_user_id=OWNER),
            ]
        )
        await db.commit()

        async def case_ids(viewer):
            _threat, cases = await fetch_threat_columns(db, [e.id], viewer=viewer)
            return sorted(cases.get(e.id, []))

        assert await case_ids(owner) == [1, 2]
        assert await case_ids(admin) == [1, 2]
        assert await case_ids(stranger) == [2], "an unshared case leaked its existence and membership"
        assert await case_ids(anonymous) == [2]

    async def test_the_current_case_is_excluded_from_its_own_graph(self, db):
        """`in_case` must mean "also in another case", or every node in a case graph is flagged."""
        e = await _entity(db, 1, "10.0.0.1")
        db.add(InvestigationCase(id=1, name="This one", created_by_user_id=OWNER, is_shared=True))
        await db.commit()
        db.add(CaseEntityLink(case_id=1, entity_id=e.id, added_by_user_id=OWNER))
        await db.commit()

        _threat, cases = await fetch_threat_columns(db, [e.id], viewer=owner, current_case_id=1)
        assert cases.get(e.id) is None


@pytest.mark.asyncio
class TestEnrichmentVerdict:
    async def test_only_the_derived_integer_crosses_the_wire(self, db):
        """`response_json` and the decrypted token never leave the server."""
        e = await _entity(db, 1, "1.2.3.4")
        db.add(EnrichmentService(id=1, name="VT", provider_key="virustotal", link_template="https://x/{value}"))
        await db.commit()
        db.add(
            EntityEnrichmentResult(
                entity_id=e.id,
                service_id=1,
                ok=True,
                response_json='{"secret": "do not ship this"}',
                summary_json=json.dumps({"detections": "9 / 70", "malicious": 9, "suspicious": 0}),
            )
        )
        await db.commit()

        threat, _ = await fetch_threat_columns(db, [e.id], viewer=None)
        assert threat[e.id].verdict == 4  # ENRICHMENT_VERDICTS index for "malicious"

        payload = await build_case_graph(db, [e.id], viewer=None, job_edges=False)
        assert "do not ship this" not in json.dumps(payload)

    async def test_a_failed_lookup_is_not_a_verdict(self, db):
        e = await _entity(db, 1, "1.2.3.4")
        db.add(EnrichmentService(id=1, name="VT", provider_key="virustotal", link_template="https://x/{value}"))
        await db.commit()
        db.add(EntityEnrichmentResult(entity_id=e.id, service_id=1, ok=False, error_message="429", summary_json=None))
        await db.commit()

        threat, _ = await fetch_threat_columns(db, [e.id], viewer=None)
        assert e.id not in threat

    async def test_the_strongest_verdict_across_services_wins(self, db):
        e = await _entity(db, 1, "1.2.3.4")
        db.add_all(
            [
                EnrichmentService(id=1, name="VT", provider_key="virustotal", link_template="https://x/{value}"),
                EnrichmentService(id=2, name="Abuse", provider_key="abuseipdb", link_template="https://y/{value}"),
            ]
        )
        await db.commit()
        db.add_all(
            [
                EntityEnrichmentResult(entity_id=e.id, service_id=1, ok=True, summary_json=json.dumps({"detections": "0 / 70", "malicious": 0})),
                EntityEnrichmentResult(entity_id=e.id, service_id=2, ok=True, summary_json=json.dumps({"abuse_score": 90})),
            ]
        )
        await db.commit()

        threat, _ = await fetch_threat_columns(db, [e.id], viewer=None)
        assert threat[e.id].verdict == 4


@pytest.mark.asyncio
class TestPayloadIntegration:
    async def test_the_columns_reach_the_payload_for_the_right_viewer(self, db):
        await _job(db, 1, private=True, owner_id=OWNER)
        e = await _entity(db, 1, "10.0.0.1")
        await _finding(db, fid=1, job_id=1, entity_ids=[e.id], severity=Severity.CRITICAL, tags=["attack.impact"])
        db.add(EntityJobLink(entity_id=e.id, job_id=1))
        await db.commit()

        for viewer, expected in ((owner, "critical"), (stranger, None), (anonymous, None)):
            payload = await build_entity_graph(db, e.id, viewer=viewer)
            node = decode_graph(payload)["nodes"][0]["data"]
            # `.get`, not `[...]`: with nothing visible the whole column is omitted rather
            # than emitted as zeros, which is what makes `"sv" in n` a meaningful probe.
            assert node.get("severity") == expected, f"viewer={viewer}"
            assert node.get("tactic") == ("impact" if expected else None)

    async def test_threat_columns_are_omitted_entirely_when_nothing_applies(self, db):
        """An all-zero column still costs a byte per node; absence is a meaningful probe."""
        e = await _entity(db, 1, "10.0.0.1")
        payload = await build_case_graph(db, [e.id], viewer=None, job_edges=False)
        assert "sv" not in payload["n"]
        assert "tc" not in payload["n"]

    async def test_exports_skip_the_threat_queries(self, db):
        """GraphML has no way to explain a verdict integer, and the queries are the
        expensive half of the request."""
        await _job(db, 1)
        e = await _entity(db, 1, "10.0.0.1")
        await _finding(db, fid=1, job_id=1, entity_ids=[e.id])
        payload = await build_entity_graph(db, e.id, viewer=None, threat=False)
        assert "sv" not in payload["n"]
