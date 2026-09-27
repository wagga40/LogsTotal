"""Admin CRUD for AiProvider — the analogue of `enrichment_admin.py`.

All routes require superuser. Form-based with 303 redirects, matching the existing admin
convention. The shared `_validated_provider_form()` serves create *and* update: if those two
drift, an admin can edit a row into a state the create form would have rejected, and the
breakage surfaces later as a failed request rather than a rejected save.

`base_url` is checked here with `validate_url_syntax` — the DNS-free half. Resolution
happens at request time in `app/ai/client.py`, which is the only moment it protects
anything, and refusing to *save* a provider whose host is momentarily down would be wrong.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity
from app.ai.providers import PROVIDER_BASE_URL_HINTS, PROVIDER_KINDS, PROVIDER_LABELS, normalize_base_url
from app.auth.api_tokens import encrypt_secret
from app.auth.users import current_superuser
from app.config import settings
from app.database import get_async_session
from app.intel.webhooks import WebhookError, validate_url_syntax
from app.models import AiProvider, CaseAiAnalysis, JobAiAnalysis, User
from app.templates_config import templates

router = APIRouter(prefix="/admin/ai")

_NAME_MAX = 80
_MODEL_MAX = 200
_URL_MAX = 500
_SYSTEM_PROMPT_MAX = 8000
# Bounds an admin cannot usefully cross. The upper end is a guard against a typo turning
# one click into an unbounded bill, not a considered ceiling on model capability.
_MAX_OUTPUT_TOKENS_RANGE = (1, 200_000)
_MAX_PROMPT_CHARS_RANGE = (1, 2_000_000)
_TIMEOUT_RANGE = (5, 3600)


def _validated_provider_form(
    *,
    name: str,
    kind: str,
    base_url: str,
    model: str,
    system_prompt: str,
    temperature: float,
    max_output_tokens: int,
    timeout_seconds: int,
    case_system_prompt: str = "",
    job_max_prompt_chars: int | None = None,
    case_max_prompt_chars: int | None = None,
) -> dict:
    """Validate + normalise the shared provider fields for create and update."""
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Name is required")
    if len(name) > _NAME_MAX:
        raise HTTPException(400, f"Name too long (max {_NAME_MAX} chars)")

    kind = (kind or "").strip().lower()
    if kind not in PROVIDER_KINDS:
        raise HTTPException(400, f"Invalid kind (must be one of {', '.join(PROVIDER_KINDS)})")

    # Normalised before validation and before storage: pasting the full endpoint URL out of
    # a provider's own docs is the default behaviour, and the stored value should be the one
    # that will actually be used rather than something the request path silently rewrites.
    base_url = normalize_base_url(base_url, kind)
    if not base_url:
        raise HTTPException(400, "Base URL is required")
    if len(base_url) > _URL_MAX:
        raise HTTPException(400, f"Base URL too long (max {_URL_MAX} chars)")
    try:
        validate_url_syntax(base_url)
    except WebhookError as exc:
        raise HTTPException(400, f"Base URL rejected: {exc}") from exc

    model = (model or "").strip()
    if not model:
        raise HTTPException(400, "Model is required")
    if len(model) > _MODEL_MAX:
        raise HTTPException(400, f"Model too long (max {_MODEL_MAX} chars)")

    if system_prompt and len(system_prompt) > _SYSTEM_PROMPT_MAX:
        raise HTTPException(400, f"System prompt too long (max {_SYSTEM_PROMPT_MAX} chars)")

    if case_system_prompt and len(case_system_prompt) > _SYSTEM_PROMPT_MAX:
        raise HTTPException(400, f"Case system prompt too long (max {_SYSTEM_PROMPT_MAX} chars)")

    if not 0.0 <= temperature <= 2.0:
        raise HTTPException(400, "Temperature must be between 0.0 and 2.0")

    lo, hi = _MAX_OUTPUT_TOKENS_RANGE
    if not lo <= max_output_tokens <= hi:
        raise HTTPException(400, f"Max output tokens must be between {lo} and {hi}")

    lo, hi = _MAX_PROMPT_CHARS_RANGE
    for label, value in (("Job", job_max_prompt_chars), ("Case", case_max_prompt_chars)):
        if value is not None and not lo <= value <= hi:
            raise HTTPException(400, f"{label} max prompt size must be between {lo} and {hi} characters")

    lo, hi = _TIMEOUT_RANGE
    if not lo <= timeout_seconds <= hi:
        raise HTTPException(400, f"Timeout must be between {lo} and {hi} seconds")

    return {
        "name": name,
        "kind": kind,
        "base_url": base_url,
        "model": model,
        "system_prompt": (system_prompt or "").strip() or None,
        "case_system_prompt": (case_system_prompt or "").strip() or None,
        "temperature": float(temperature),
        "max_output_tokens": int(max_output_tokens),
        "job_max_prompt_chars": job_max_prompt_chars,
        "case_max_prompt_chars": case_max_prompt_chars,
        "timeout_seconds": int(timeout_seconds),
    }


async def _clear_other_defaults(db: AsyncSession, keep_id: int | None) -> None:
    """At most one provider is the default — the same single-valued rule as WorkflowDef."""
    stmt = update(AiProvider).values(is_default=False)
    if keep_id is not None:
        stmt = stmt.where(AiProvider.id != keep_id)
    await db.execute(stmt)


@router.get("", response_class=HTMLResponse)
async def ai_list(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    rows = (await db.execute(select(AiProvider).order_by(AiProvider.is_default.desc(), AiProvider.name))).scalars().all()
    providers = [
        {
            "id": r.id,
            "name": r.name,
            "kind": r.kind,
            "kind_label": PROVIDER_LABELS.get(r.kind, r.kind),
            "base_url": r.base_url,
            "model": r.model,
            "system_prompt": r.system_prompt,
            "case_system_prompt": r.case_system_prompt,
            "temperature": r.temperature,
            "max_output_tokens": r.max_output_tokens,
            "job_max_prompt_chars": r.job_max_prompt_chars,
            "case_max_prompt_chars": r.case_max_prompt_chars,
            "timeout_seconds": r.timeout_seconds,
            "has_api_token": bool(r.api_token_encrypted),
            "enabled": r.enabled,
            "is_default": r.is_default,
            "notes": r.notes,
        }
        for r in rows
    ]
    return templates.TemplateResponse(
        request,
        "admin/ai.html",
        {
            "request": request,
            "user": user,
            "providers": providers,
            "kinds": [(k, PROVIDER_LABELS.get(k, k)) for k in PROVIDER_KINDS],
            "base_url_hints": PROVIDER_BASE_URL_HINTS,
            "default_max_prompt_chars": settings.ai_max_prompt_chars,
            "test_result": request.query_params.get("test_ok"),
            "test_error": request.query_params.get("test_error"),
        },
    )


@router.post("")
async def ai_create(
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
    name: str = Form(...),
    kind: str = Form("openai"),
    base_url: str = Form(...),
    model: str = Form(...),
    api_token: str = Form(""),
    system_prompt: str = Form(""),
    case_system_prompt: str = Form(""),
    temperature: float = Form(0.2),
    max_output_tokens: int = Form(20_000),
    job_max_prompt_chars: int | None = Form(None),
    case_max_prompt_chars: int | None = Form(None),
    timeout_seconds: int = Form(300),
    enabled: int = Form(1),
    is_default: int = Form(0),
    notes: str = Form(""),
):
    fields = _validated_provider_form(
        name=name,
        kind=kind,
        base_url=base_url,
        model=model,
        system_prompt=system_prompt,
        case_system_prompt=case_system_prompt,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        job_max_prompt_chars=job_max_prompt_chars,
        case_max_prompt_chars=case_max_prompt_chars,
        timeout_seconds=timeout_seconds,
    )
    provider = AiProvider(
        **fields,
        api_token_encrypted=encrypt_secret(api_token) if api_token.strip() else None,
        enabled=bool(enabled),
        is_default=bool(is_default),
        notes=notes.strip() or None,
    )
    db.add(provider)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(400, f"A provider named {name!r} already exists.") from None
    if provider.is_default:
        await _clear_other_defaults(db, provider.id)
        await db.commit()
    # The base URL and model, never the token: an AI provider is where job data starts
    # leaving the instance, so "which endpoint was pointed at" is the interesting fact.
    await activity.record(
        "admin.provider.create",
        request=request,
        user=user,
        target_type="ai_provider",
        target_id=str(provider.id),
        summary=f"{provider.name} ({provider.kind})",
        meta={"base_url": provider.base_url, "model": provider.model},
    )
    return RedirectResponse("/admin/ai?created=1", status_code=303)


@router.post("/{provider_id}")
async def ai_update(
    provider_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
    name: str = Form(...),
    kind: str = Form("openai"),
    base_url: str = Form(...),
    model: str = Form(...),
    api_token: str = Form(""),
    system_prompt: str = Form(""),
    case_system_prompt: str = Form(""),
    temperature: float = Form(0.2),
    max_output_tokens: int = Form(20_000),
    job_max_prompt_chars: int | None = Form(None),
    case_max_prompt_chars: int | None = Form(None),
    timeout_seconds: int = Form(300),
    enabled: int = Form(1),
    is_default: int = Form(0),
    notes: str = Form(""),
):
    provider = await db.get(AiProvider, provider_id)
    if not provider:
        raise HTTPException(404, "Provider not found")
    fields = _validated_provider_form(
        name=name,
        kind=kind,
        base_url=base_url,
        model=model,
        system_prompt=system_prompt,
        case_system_prompt=case_system_prompt,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        job_max_prompt_chars=job_max_prompt_chars,
        case_max_prompt_chars=case_max_prompt_chars,
        timeout_seconds=timeout_seconds,
    )
    for attr, value in fields.items():
        setattr(provider, attr, value)
    # Empty input means "leave the existing token alone" — same rule as enrichment.
    if api_token.strip():
        provider.api_token_encrypted = encrypt_secret(api_token)
    provider.enabled = bool(enabled)
    provider.is_default = bool(is_default)
    provider.notes = notes.strip() or None

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(400, f"A provider named {name!r} already exists.") from None
    if provider.is_default:
        await _clear_other_defaults(db, provider.id)
        await db.commit()
    await activity.record(
        "admin.provider.update",
        request=request,
        user=user,
        target_type="ai_provider",
        target_id=str(provider.id),
        summary=provider.name,
        meta={"base_url": provider.base_url, "model": provider.model},
    )
    return RedirectResponse("/admin/ai?updated=1", status_code=303)


@router.post("/{provider_id}/toggle")
async def ai_toggle(
    provider_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    provider = await db.get(AiProvider, provider_id)
    if not provider:
        raise HTTPException(404, "Provider not found")
    provider.enabled = not bool(provider.enabled)
    await db.commit()
    await activity.record(
        "admin.provider.toggle",
        request=request,
        user=user,
        target_type="ai_provider",
        target_id=str(provider.id),
        summary=f"{provider.name} {'enabled' if provider.enabled else 'disabled'}",
    )
    return RedirectResponse("/admin/ai?toggled=1", status_code=303)


@router.post("/{provider_id}/delete")
async def ai_delete(
    provider_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    provider = await db.get(AiProvider, provider_id)
    if not provider:
        raise HTTPException(404, "Provider not found")
    # Past runs are HISTORY, not a cache: null the FK and keep them. `provider_name` and
    # `model` were snapshotted on each row for exactly this, so every past analysis stays
    # readable and correctly attributed. (`enrichment_delete` hard-deletes its rows — the
    # opposite call, for the opposite kind of data.)
    name = provider.name
    await db.execute(update(JobAiAnalysis).where(JobAiAnalysis.provider_id == provider_id).values(provider_id=None))
    await db.execute(update(CaseAiAnalysis).where(CaseAiAnalysis.provider_id == provider_id).values(provider_id=None))
    await db.delete(provider)
    await db.commit()
    await activity.record("admin.provider.delete", request=request, user=user, target_type="ai_provider", target_id=str(provider_id), summary=name)
    return RedirectResponse("/admin/ai?deleted=1", status_code=303)


# Longest suffix `_copy_name` can append, so the base name is trimmed to leave room for it
# rather than producing a name the 80-char column would truncate or reject.
_COPY_SUFFIX_MAX = len(" (copy 99)")
_COPY_ATTEMPTS = 99


async def _copy_name(db: AsyncSession, base: str) -> str:
    """A free name derived from *base*: "X (copy)", then "X (copy 2)", …

    `AiProvider.name` is unique, which is what makes duplication need this at all — and it
    is the right constraint to keep, because the name is what an analyst picks from the run
    dropdown and two identical entries there are useless. So the copy is renamed rather than
    the constraint relaxed.
    """
    stem = base
    if len(stem) + _COPY_SUFFIX_MAX > 80:
        stem = stem[: 80 - _COPY_SUFFIX_MAX].rstrip()
    taken = {n for (n,) in (await db.execute(select(AiProvider.name))).all()}
    for i in range(1, _COPY_ATTEMPTS + 1):
        candidate = f"{stem} (copy)" if i == 1 else f"{stem} (copy {i})"
        if candidate not in taken:
            return candidate
    # 99 copies of one provider is not a naming problem any more.
    raise HTTPException(400, "Too many copies of that provider already exist — rename or delete some first.")


@router.post("/{provider_id}/duplicate")
async def ai_duplicate(
    provider_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Copy a provider under a free name.

    The reason to want this is that providers differ from each other in one field: the same
    endpoint and the same token, a different model. Re-entering a base URL and re-pasting a
    key to change one word is where a typo comes from, and a mistyped base URL fails as a
    404 that reads like a bad model name.

    Two fields deliberately do **not** survive the copy:

    * ``is_default`` — at most one provider holds it, so a copy claiming it would silently
      demote the original. The copy is never the default; make it so explicitly if you mean
      it.
    * ``name`` — unique by constraint, and renamed by :func:`_copy_name` rather than left
      for the admin to resolve against an IntegrityError.

    The **token is copied**, encrypted blob and all. It is the same key on the same instance
    for the same admin, and a duplicate that silently lost its credential would fail at the
    first run with an auth error pointing at nothing.
    """
    source = await db.get(AiProvider, provider_id)
    if not source:
        raise HTTPException(404, "Provider not found")

    clone = AiProvider(
        name=await _copy_name(db, source.name),
        kind=source.kind,
        base_url=source.base_url,
        model=source.model,
        api_token_encrypted=source.api_token_encrypted,
        system_prompt=source.system_prompt,
        case_system_prompt=source.case_system_prompt,
        temperature=source.temperature,
        max_output_tokens=source.max_output_tokens,
        job_max_prompt_chars=source.job_max_prompt_chars,
        case_max_prompt_chars=source.case_max_prompt_chars,
        timeout_seconds=source.timeout_seconds,
        enabled=source.enabled,
        is_default=False,
        notes=source.notes,
    )
    db.add(clone)
    try:
        await db.commit()
    except IntegrityError:
        # Another admin took the name between the scan and the insert. Rare, and a retry
        # would just race again; saying so beats a 500.
        await db.rollback()
        raise HTTPException(400, "That name was taken while the copy was being made. Try again.") from None
    # This route creates a provider — an endpoint job data can be sent to, carrying a copy
    # of the source's token — so it is recorded as a create.
    await activity.record(
        "admin.provider.duplicate",
        request=request,
        user=user,
        target_type="ai_provider",
        target_id=str(clone.id),
        summary=f"{clone.name} (from {source.name})",
    )
    return RedirectResponse("/admin/ai?duplicated=1", status_code=303)


@router.post("/{provider_id}/clear-token")
async def ai_clear_token(
    provider_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    provider = await db.get(AiProvider, provider_id)
    if not provider:
        raise HTTPException(404, "Provider not found")
    provider.api_token_encrypted = None
    await db.commit()
    await activity.record("admin.provider.clear_token", request=request, user=user, target_type="ai_provider", target_id=str(provider.id), summary=provider.name)
    return RedirectResponse("/admin/ai?token_cleared=1", status_code=303)


@router.post("/{provider_id}/test")
async def ai_test(
    provider_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    """Send a trivial prompt to prove reachability, credentials and model name.

    Runs inline in a threadpool rather than through Huey, in the spirit of the webhook
    "send test": the admin clicking it is trying to *see* the failure, and a diagnostic
    whose result lands somewhere else a minute later is not a diagnostic. It is also
    deliberately not retried, for the same reason.
    """
    from starlette.concurrency import run_in_threadpool

    from app.ai.client import run_completion
    from app.auth.api_tokens import decrypt_secret
    from app.config import settings

    provider = await db.get(AiProvider, provider_id)
    if not provider:
        raise HTTPException(404, "Provider not found")

    token = decrypt_secret(provider.api_token_encrypted) if provider.api_token_encrypted else None
    text, _usage, ms, error = await run_in_threadpool(
        run_completion,
        kind=provider.kind,
        base_url=provider.base_url,
        model=provider.model,
        token=token,
        system="You are a connectivity test. Reply with the single word OK and nothing else.",
        user="Reply with OK.",
        temperature=0.0,
        # Generous even for a one-word answer: a reasoning model spends output tokens
        # thinking first, and a test that fails only because the budget was tight would
        # send an admin hunting a configuration problem that does not exist.
        max_output_tokens=min(provider.max_output_tokens, 1000),
        timeout=float(provider.timeout_seconds or 300),
        require_public=settings.ai_require_public_host,
    )
    from urllib.parse import quote

    # Recorded either way: a test is a real completion against a real endpoint, so it is
    # data egress like any other run, and a failing one is what an admin will later want
    # to correlate with a configuration change.
    await activity.record(
        "admin.provider.test",
        request=request,
        user=user,
        target_type="ai_provider",
        target_id=str(provider.id),
        summary=f"{provider.name}: {'failed' if error else f'replied in {ms} ms'}",
        outcome=activity.OUTCOME_FAILURE if error else activity.OUTCOME_SUCCESS,
        meta={"base_url": provider.base_url, "model": provider.model, "duration_ms": ms},
    )
    if error:
        return RedirectResponse(f"/admin/ai?test_error={quote(error[:300])}", status_code=303)
    snippet = " ".join((text or "").split())[:60]
    return RedirectResponse(f"/admin/ai?test_ok={quote(f'{provider.name} replied in {ms} ms: {snippet}')}", status_code=303)
