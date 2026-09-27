"""Admin CRUD for ApiToken bearer tokens.

Tokens are stored only as SHA-256 hashes. The plaintext is rendered **once** on the
creation success page; navigating away makes it unrecoverable.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity
from app.auth.api_tokens import KNOWN_SCOPES, basic_auth_in_front, generate_token, validate_scopes
from app.auth.users import current_superuser
from app.database import get_async_session
from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.models import ApiToken, User
from app.templates_config import templates

router = APIRouter(prefix="/admin/api-tokens")

_NAME_MAX = 120


def _to_view(t: ApiToken) -> dict:
    try:
        scopes = json_loads(t.scopes_json or "[]")
    except (ValueError, TypeError):
        scopes = []
    return {
        "id": t.id,
        "name": t.name,
        "prefix": t.prefix,
        "scopes": scopes,
        "last_used_at": t.last_used_at,
        "expires_at": t.expires_at,
        "revoked_at": t.revoked_at,
        "created_at": t.created_at,
        "active": t.revoked_at is None and (t.expires_at is None or t.expires_at > datetime.now(UTC).replace(tzinfo=None)),
    }


@router.get("", response_class=HTMLResponse)
async def api_tokens_list(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    rows = (await db.execute(select(ApiToken).order_by(ApiToken.revoked_at.is_(None).desc(), ApiToken.created_at.desc()))).scalars().all()
    return templates.TemplateResponse(
        request,
        "admin/api_tokens.html",
        {
            "request": request,
            "user": user,
            "tokens": [_to_view(t) for t in rows],
            "known_scopes": list(KNOWN_SCOPES),
            "new_token_plaintext": None,
            "basic_auth_in_front": basic_auth_in_front(request),
        },
    )


@router.post("", response_class=HTMLResponse)
async def api_token_create(
    request: Request,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
    name: str = Form(...),
    scopes: list[str] = Form(default_factory=list),
    expires_at: str = Form(""),
):
    name = (name or "").strip()
    if not name:
        raise HTTPException(400, "Name is required")
    if len(name) > _NAME_MAX:
        raise HTTPException(400, f"Name too long (max {_NAME_MAX} chars)")
    scope_list = validate_scopes(scopes)
    if not scope_list:
        raise HTTPException(400, "At least one valid scope is required")

    expires_dt = None
    if expires_at.strip():
        try:
            expires_dt = datetime.fromisoformat(expires_at)
        except ValueError as exc:
            raise HTTPException(400, f"Invalid expires_at: {exc}") from exc
        # `ApiToken.expires_at` is TIMESTAMP WITHOUT TIME ZONE, and the admin form accepts
        # anything `fromisoformat` parses — including an offset-bearing value, which
        # asyncpg refuses to bind. Normalise to naive UTC, matching how `revoked_at` and
        # `last_used_at` are written.
        if expires_dt.tzinfo is not None:
            expires_dt = expires_dt.astimezone(UTC).replace(tzinfo=None)

    plaintext, digest, prefix = generate_token()
    token = ApiToken(
        name=name,
        token_hash=digest,
        prefix=prefix,
        scopes_json=json_dumps(scope_list),
        created_by_user_id=user.id,
        expires_at=expires_dt,
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    # The scopes and the 8-char prefix, never the plaintext: the whole point of the
    # once-only display is that the secret exists in no durable store, including this one.
    await activity.record(
        "admin.token.create",
        request=request,
        user=user,
        target_type="api_token",
        target_id=str(token.id),
        summary=f"{name} ({token.prefix})",
        meta={"scopes": scope_list, "prefix": token.prefix},
    )

    # Render the list page with the plaintext shown ONCE.
    rows = (await db.execute(select(ApiToken).order_by(ApiToken.revoked_at.is_(None).desc(), ApiToken.created_at.desc()))).scalars().all()
    return templates.TemplateResponse(
        request,
        "admin/api_tokens.html",
        {
            "request": request,
            "user": user,
            "tokens": [_to_view(t) for t in rows],
            "known_scopes": list(KNOWN_SCOPES),
            "new_token_plaintext": plaintext,
            "new_token_name": name,
            "basic_auth_in_front": basic_auth_in_front(request),
        },
    )


@router.post("/{token_id}/revoke")
async def api_token_revoke(
    token_id: int,
    request: Request = None,
    db: AsyncSession = Depends(get_async_session),
    user: User = Depends(current_superuser),
):
    token = await db.get(ApiToken, token_id)
    if not token:
        raise HTTPException(404, "Token not found")
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC).replace(tzinfo=None)
        await db.commit()
        await activity.record(
            "admin.token.revoke",
            request=request,
            user=user,
            target_type="api_token",
            target_id=str(token.id),
            summary=f"{token.name} ({token.prefix})",
        )
    return RedirectResponse("/admin/api-tokens?revoked=1", status_code=303)
