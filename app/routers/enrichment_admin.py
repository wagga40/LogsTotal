"""Admin CRUD for EnrichmentService.

All routes require superuser. UI is form-based (page reload after each action) to match
the existing admin convention.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity
from app.auth.api_tokens import encrypt_secret
from app.auth.users import current_superuser
from app.constants import ENTITY_TYPES, parse_entity_types
from app.database import get_async_session
from app.intel.live_enrichment import validate_api_template
from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.models import EnrichmentService, EntityEnrichmentResult, User
from app.templates_config import templates

router = APIRouter(prefix="/admin/enrichment")

_NAME_MAX = 80
_TEMPLATE_MAX = 500
_METHOD_VALUES = {"GET", "POST"}


@router.get("", response_class=HTMLResponse)
async def enrichment_list(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    rows = (await db.execute(select(EnrichmentService).order_by(EnrichmentService.display_order, EnrichmentService.name))).scalars().all()
    services = []
    for r in rows:
        try:
            types = json_loads(r.entity_types or "[]")
        except (ValueError, TypeError):
            types = []
        services.append(
            {
                "id": r.id,
                "name": r.name,
                "provider_key": r.provider_key,
                "entity_types": types,
                "link_template": r.link_template,
                "api_template": r.api_template,
                "api_method": r.api_method,
                "api_headers_json": r.api_headers_json,
                "has_api_token": bool(r.api_token_encrypted),
                "enabled": r.enabled,
                "display_order": r.display_order,
                "notes": r.notes,
            }
        )
    return templates.TemplateResponse(
        request,
        "admin/enrichment.html",
        # Canonical order, not alphabetical: this is the same nine values the dashboard,
        # the legend and the type badges list, and a checkbox row that disagrees with every
        # other list of them reads as a different set.
        {"request": request, "user": user, "services": services, "entity_types": list(ENTITY_TYPES)},
    )


def _validated_service_form(
    *,
    name: str,
    provider_key: str,
    entity_types: str | list[str],
    link_template: str,
    api_template: str,
    api_method: str,
    api_headers_json: str,
) -> dict:
    """Validate + normalise the shared service form fields for create and update.

    Shared so the two routes cannot drift: otherwise an admin could edit a service into a
    state the create form would have rejected — and a malformed headers blob would only
    surface later, as a failed outbound lookup.
    """
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Name is required")
    if len(name) > _NAME_MAX:
        raise HTTPException(400, f"Name too long (max {_NAME_MAX} chars)")

    types_list = parse_entity_types(entity_types)
    if not types_list:
        raise HTTPException(400, "At least one valid entity_type is required")

    method = api_method.strip().upper() or "GET"
    if method not in _METHOD_VALUES:
        raise HTTPException(400, f"Invalid api_method (must be one of {sorted(_METHOD_VALUES)})")

    if api_headers_json.strip():
        try:
            if not isinstance(json_loads(api_headers_json), dict):
                raise ValueError("must be a JSON object")
        except (ValueError, TypeError) as exc:
            raise HTTPException(400, f"Invalid api_headers_json: {exc}") from exc

    if link_template and len(link_template) > _TEMPLATE_MAX:
        raise HTTPException(400, f"link_template too long (max {_TEMPLATE_MAX} chars)")
    if api_template and len(api_template) > _TEMPLATE_MAX:
        raise HTTPException(400, f"api_template too long (max {_TEMPLATE_MAX} chars)")

    provider = (provider_key or "").strip() or None
    ok_tpl, tpl_reason = validate_api_template(api_template.strip(), provider)
    if not ok_tpl:
        raise HTTPException(400, tpl_reason)

    return {
        "name": name,
        "provider_key": provider,
        "entity_types": json_dumps(types_list),
        "link_template": link_template.strip() or None,
        "api_template": api_template.strip() or None,
        "api_method": method,
        "api_headers_json": api_headers_json.strip() or None,
    }


@router.post("")
async def enrichment_create(
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
    name: str = Form(...),
    provider_key: str = Form(""),
    entity_types: list[str] = Form([]),
    link_template: str = Form(""),
    api_template: str = Form(""),
    api_method: str = Form("GET"),
    api_headers_json: str = Form(""),
    api_token: str = Form(""),
    enabled: int = Form(1),
    display_order: int = Form(100),
    notes: str = Form(""),
):
    fields = _validated_service_form(
        name=name,
        provider_key=provider_key,
        entity_types=entity_types,
        link_template=link_template,
        api_template=api_template,
        api_method=api_method,
        api_headers_json=api_headers_json,
    )

    svc = EnrichmentService(
        **fields,
        api_token_encrypted=encrypt_secret(api_token) if api_token else None,
        enabled=bool(enabled),
        display_order=int(display_order),
        notes=notes.strip() or None,
    )
    db.add(svc)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(400, f"A service named {name!r} already exists.") from None
    # The outbound template, never the token: this row decides where entity values are
    # sent, which is the part worth being able to reconstruct later.
    await activity.record(
        "admin.enrichment.create",
        request=request,
        user=user,
        target_type="enrichment_service",
        target_id=str(svc.id),
        summary=svc.name,
        meta={"api_template": svc.api_template, "entity_types": svc.entity_types},
    )
    return RedirectResponse("/admin/enrichment?created=1", status_code=303)


@router.post("/{service_id}")
async def enrichment_update(
    service_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
    name: str = Form(...),
    provider_key: str = Form(""),
    entity_types: list[str] = Form([]),
    link_template: str = Form(""),
    api_template: str = Form(""),
    api_method: str = Form("GET"),
    api_headers_json: str = Form(""),
    api_token: str = Form(""),
    enabled: int = Form(1),
    display_order: int = Form(100),
    notes: str = Form(""),
):
    svc = await db.get(EnrichmentService, service_id)
    if not svc:
        raise HTTPException(404, "Service not found")
    fields = _validated_service_form(
        name=name,
        provider_key=provider_key,
        entity_types=entity_types,
        link_template=link_template,
        api_template=api_template,
        api_method=api_method,
        api_headers_json=api_headers_json,
    )
    for attr, value in fields.items():
        setattr(svc, attr, value)
    # Only update token if a new one was supplied; empty input means "leave existing".
    if api_token.strip():
        svc.api_token_encrypted = encrypt_secret(api_token)
    svc.enabled = bool(enabled)
    svc.display_order = int(display_order)
    svc.notes = notes.strip() or None

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(400, f"A service named {name!r} already exists.") from None
    await activity.record(
        "admin.enrichment.update",
        request=request,
        user=user,
        target_type="enrichment_service",
        target_id=str(svc.id),
        summary=svc.name,
        meta={"api_template": svc.api_template},
    )
    return RedirectResponse("/admin/enrichment?updated=1", status_code=303)


@router.post("/{service_id}/toggle")
async def enrichment_toggle(
    service_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    svc = await db.get(EnrichmentService, service_id)
    if not svc:
        raise HTTPException(404, "Service not found")
    svc.enabled = not bool(svc.enabled)
    await db.commit()
    await activity.record(
        "admin.enrichment.toggle",
        request=request,
        user=user,
        target_type="enrichment_service",
        target_id=str(svc.id),
        summary=f"{svc.name} {'enabled' if svc.enabled else 'disabled'}",
    )
    return RedirectResponse("/admin/enrichment?toggled=1", status_code=303)


@router.post("/{service_id}/delete")
async def enrichment_delete(
    service_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    svc = await db.get(EnrichmentService, service_id)
    if not svc:
        raise HTTPException(404, "Service not found")
    # Drop cached enrichment results first — no ORM cascade configured on this FK.
    from sqlalchemy import delete as _delete

    name = svc.name
    await db.execute(_delete(EntityEnrichmentResult).where(EntityEnrichmentResult.service_id == service_id))
    await db.delete(svc)
    await db.commit()
    await activity.record("admin.enrichment.delete", request=request, user=user, target_type="enrichment_service", target_id=str(service_id), summary=name)
    return RedirectResponse("/admin/enrichment?deleted=1", status_code=303)


@router.post("/{service_id}/clear-token")
async def enrichment_clear_token(
    service_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    svc = await db.get(EnrichmentService, service_id)
    if not svc:
        raise HTTPException(404, "Service not found")
    svc.api_token_encrypted = None
    await db.commit()
    await activity.record("admin.enrichment.clear_token", request=request, user=user, target_type="enrichment_service", target_id=str(svc.id), summary=svc.name)
    return RedirectResponse("/admin/enrichment?token_cleared=1", status_code=303)
