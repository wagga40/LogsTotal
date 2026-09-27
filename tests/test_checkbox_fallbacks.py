"""A checkbox whose server default is "on" needs a hidden `0` in front of it.

An unticked checkbox is simply absent from the POST body. For a route whose `Form()` default
is 1 — which scripted callers rely on — absence means "on", so the box in the form could
never switch the thing off. Three of them could not:

* "Also add each job's entities" on the case's Add jobs dialog and the jobs-list bulk bar;
* "Enabled" on an enrichment service, create and edit — editing a disabled service to fix a
  typo re-enabled it, and started sending lookups to the vendor again;
* "Enabled" on an AI provider, the same way.

The fix is the hidden input, sent first: an unticked form posts `0`, a ticked one posts
`0` then `1`, and the last value wins. The routes' defaults stay 1 for API callers.
"""

from __future__ import annotations

import re

import pytest
from sqlalchemy import select

pytestmark = pytest.mark.anyio

_PAIR = re.compile(r'<input type="hidden" name="(?P<name>\w+)" value="0">\s*(?:<[^>]*>\s*)?<input type="checkbox" name="(?P=name)" value="1"')


async def _checkbox_names_with_fallback(client, path):
    body = (await client.get(path)).text
    return {m.group("name") for m in _PAIR.finditer(body)}


async def test_the_forms_carry_the_fallback(admin_client, async_db):
    from app.models import AiProvider, AnalysisJob, EnrichmentService, InvestigationCase, JobStatus, LogFile, WorkflowDef

    wf, lf = WorkflowDef(name="w", tasks_yaml="tasks: []", log_types="[]"), LogFile(original_filename="a.evtx", stored_filename="s", sha256="a" * 64, size_bytes=1)
    async_db.add_all(
        [
            wf,
            lf,
            InvestigationCase(name="c", is_shared=True),
            EnrichmentService(name="S", entity_types='["hash"]', enabled=False),
            AiProvider(name="P", kind="openai", base_url="http://127.0.0.1:1/v1", model="m", enabled=False),
        ]
    )
    await async_db.flush()
    async_db.add(AnalysisJob(file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED))
    await async_db.commit()
    case_id = (await async_db.execute(select(InvestigationCase.id))).scalar_one()

    assert "include_entities" in await _checkbox_names_with_fallback(admin_client, f"/intel/cases/{case_id}")
    assert "include_entities" in await _checkbox_names_with_fallback(admin_client, "/jobs")
    body = (await admin_client.get("/admin/enrichment")).text
    assert len([m for m in _PAIR.finditer(body) if m.group("name") == "enabled"]) >= 2, "create and edit"
    body = (await admin_client.get("/admin/ai")).text
    assert len([m for m in _PAIR.finditer(body) if m.group("name") == "enabled"]) >= 2, "create and edit"


async def test_the_last_value_wins_so_the_fallback_works(admin_client, async_db):
    """What an unticked edit form posts must switch a service off; a ticked one, on."""
    from app.models import EnrichmentService

    svc = EnrichmentService(name="S", entity_types='["hash"]', link_template="https://x.example/{value}", enabled=True)
    async_db.add(svc)
    await async_db.commit()
    form = {
        "name": "S",
        "provider_key": "",
        "entity_types": ["hash"],
        "link_template": "https://x.example/{value}",
        "api_template": "",
        "api_method": "GET",
        "api_headers_json": "",
        "display_order": "100",
        "notes": "",
    }

    await admin_client.post(f"/admin/enrichment/{svc.id}", data={**form, "enabled": ["0"]}, follow_redirects=False)
    await async_db.refresh(svc)
    assert svc.enabled is False

    await admin_client.post(f"/admin/enrichment/{svc.id}", data={**form, "enabled": ["0", "1"]}, follow_redirects=False)
    await async_db.refresh(svc)
    assert svc.enabled is True
