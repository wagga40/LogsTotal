"""Provider budgets survive admin forms, editing and duplication."""

import pytest
from sqlalchemy import select

from app.models import AiProvider

FORM = {"name": "Budgeted provider", "base_url": "http://localhost:11434/v1", "model": "test-model"}


async def test_default_output_and_blank_prompt_limits(admin_client, async_db, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "ai_max_prompt_chars", 75_000)
    response = await admin_client.post("/admin/ai", data={**FORM, "job_max_prompt_chars": "", "case_max_prompt_chars": ""})
    assert response.status_code == 303
    provider = await async_db.scalar(select(AiProvider))
    assert provider.max_output_tokens == 20_000
    assert provider.job_max_prompt_chars is None
    assert provider.case_max_prompt_chars is None
    response = await admin_client.get("/admin/ai")
    assert response.status_code == 200
    assert response.text.count('name="job_max_prompt_chars"') == 2
    assert response.text.count('name="case_max_prompt_chars"') == 2
    assert 'name="max_output_tokens" value="20000"' in response.text
    assert 'placeholder="75000"' in response.text


async def test_prompt_limits_create_edit_duplicate_and_clear(admin_client, async_db):
    fields = {**FORM, "job_max_prompt_chars": "12000", "case_max_prompt_chars": "90000", "max_output_tokens": "12345"}
    assert (await admin_client.post("/admin/ai", data=fields)).status_code == 303
    provider = await async_db.scalar(select(AiProvider))
    assert (provider.job_max_prompt_chars, provider.case_max_prompt_chars, provider.max_output_tokens) == (12_000, 90_000, 12_345)

    fields.update(job_max_prompt_chars="30000", case_max_prompt_chars="180000")
    assert (await admin_client.post(f"/admin/ai/{provider.id}", data=fields)).status_code == 303
    await async_db.refresh(provider)
    assert (provider.job_max_prompt_chars, provider.case_max_prompt_chars) == (30_000, 180_000)
    page = (await admin_client.get("/admin/ai")).text
    assert 'value="30000"' in page and 'value="180000"' in page

    assert (await admin_client.post(f"/admin/ai/{provider.id}/duplicate")).status_code == 303
    clone = await async_db.scalar(select(AiProvider).where(AiProvider.id != provider.id))
    assert (clone.job_max_prompt_chars, clone.case_max_prompt_chars, clone.max_output_tokens) == (30_000, 180_000, 12_345)

    fields.update(job_max_prompt_chars="", case_max_prompt_chars="")
    assert (await admin_client.post(f"/admin/ai/{provider.id}", data=fields)).status_code == 303
    await async_db.refresh(provider)
    assert provider.job_max_prompt_chars is None and provider.case_max_prompt_chars is None
    assert provider.max_output_tokens == 12_345


@pytest.mark.parametrize("scope", ["job", "case"])
@pytest.mark.parametrize("value, status", [("0", 400), ("-1", 400), ("2000001", 400), ("1.5", 422), ("nope", 422)])
async def test_invalid_prompt_limits_rejected_on_create_and_update(admin_client, async_db, scope, value, status):
    fields = {**FORM, f"{scope}_max_prompt_chars": value}
    assert (await admin_client.post("/admin/ai", data=fields)).status_code == status
    assert await async_db.scalar(select(AiProvider)) is None
    assert (await admin_client.post("/admin/ai", data=FORM)).status_code == 303
    provider = await async_db.scalar(select(AiProvider))
    assert (await admin_client.post(f"/admin/ai/{provider.id}", data=fields)).status_code == status
    await async_db.refresh(provider)
    assert provider.job_max_prompt_chars is None and provider.case_max_prompt_chars is None
