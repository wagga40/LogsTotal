"""TAXII 2.1 read-only server router. Conditionally registered when settings.taxii_enabled."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity
from app.auth.api_tokens import require_api_token
from app.config import settings
from app.database import get_async_session, parse_row_id
from app.intel.taxii import (
    DEFAULT_API_ROOT,
    STIX_MEDIA_TYPE,
    TAXII_MEDIA_TYPE,
    api_root,
    collection_by_id,
    collection_envelope,
    collections_envelope,
    discovery,
    objects_envelope,
)
from app.models import ApiToken, Entity

router = APIRouter(prefix="/taxii2")

_TAXII_HEADERS = {"Content-Type": TAXII_MEDIA_TYPE}
_STIX_HEADERS = {"Content-Type": STIX_MEDIA_TYPE}

_MAX_OBJECTS = 500


def _base_url(request: Request) -> str:
    """The URL clients are told to follow, as they reach this instance.

    Behind a TLS-terminating proxy the app sees plain HTTP, so `request.base_url` says
    `http://` — and a client following discovery's `api_roots` would send its Bearer token
    in the clear before the proxy redirected it. A Secure login cookie (`COOKIE_INSECURE`
    unset) is the deployment stating it is served over HTTPS; the cookie would not work
    otherwise, so the same statement decides the scheme advertised here.
    """
    url = request.base_url
    if settings.cookie_secure and url.scheme == "http":
        url = url.replace(scheme="https")
    return str(url).rstrip("/")


@router.get("/", response_class=JSONResponse)
async def taxii_discovery(
    request: Request,
    _token: ApiToken = Depends(require_api_token("taxii:read")),
):
    return JSONResponse(discovery(_base_url(request)), headers=_TAXII_HEADERS)


@router.get("/{root}/", response_class=JSONResponse)
async def taxii_api_root(
    root: str,
    _token: ApiToken = Depends(require_api_token("taxii:read")),
):
    if root != DEFAULT_API_ROOT:
        raise HTTPException(404, "Unknown api-root")
    return JSONResponse(api_root(), headers=_TAXII_HEADERS)


@router.get("/{root}/collections/", response_class=JSONResponse)
async def taxii_collections(
    root: str,
    _token: ApiToken = Depends(require_api_token("taxii:read")),
):
    if root != DEFAULT_API_ROOT:
        raise HTTPException(404, "Unknown api-root")
    return JSONResponse(collections_envelope(), headers=_TAXII_HEADERS)


@router.get("/{root}/collections/{collection_id}/", response_class=JSONResponse)
async def taxii_collection(
    root: str,
    collection_id: str,
    _token: ApiToken = Depends(require_api_token("taxii:read")),
):
    if root != DEFAULT_API_ROOT:
        raise HTTPException(404, "Unknown api-root")
    envelope = collection_envelope(collection_id)
    if envelope is None:
        raise HTTPException(404, "Unknown collection")
    return JSONResponse(envelope, headers=_TAXII_HEADERS)


# A NULL `last_seen_at` sorts as the oldest possible object, so the cursor has a value to
# compare against for every row.
_EPOCH = datetime(1970, 1, 1)


def _encode_cursor(seen: datetime | None, entity_id: int) -> str:
    raw = f"{(seen or _EPOCH).isoformat()}|{entity_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[datetime, int]:
    """The cursor is opaque but client-held, so it is parsed like input: an offset is folded
    to naive UTC and the id bounded, because asyncpg refuses either bind with a 500."""
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        seen_raw, _, id_raw = raw.partition("|")
        seen = datetime.fromisoformat(seen_raw)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid next cursor") from None
    entity_id = parse_row_id(id_raw)
    if entity_id is None:
        raise HTTPException(400, "Invalid next cursor")
    return (seen.astimezone(UTC).replace(tzinfo=None) if seen.tzinfo else seen), entity_id


def _parse_added_after(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "Invalid added_after timestamp") from None
    return parsed.astimezone(UTC).replace(tzinfo=None) if parsed.tzinfo else parsed


@router.get("/{root}/collections/{collection_id}/objects/", response_class=JSONResponse)
async def taxii_objects(
    root: str,
    collection_id: str,
    request: Request = None,
    limit: int = 100,
    next: str = "",  # the TAXII 2.1 parameter name, shadowing the builtin on purpose
    added_after: str = "",
    db: AsyncSession = Depends(get_async_session),
    _token: ApiToken = Depends(require_api_token("taxii:read")),
):
    """Return up to `limit` STIX 2.1 indicators wrapped in a TAXII Objects envelope.

    Newest first, paged by an opaque keyset cursor on `(last_seen_at, id)` — so a page is
    stable while new objects arrive, and two rows sharing a timestamp are neither repeated
    nor skipped. `more=true` always carries `next`; `added_after` narrows to objects seen
    after that instant, which is what an incremental poll sends.
    """
    if root != DEFAULT_API_ROOT:
        raise HTTPException(404, "Unknown api-root")
    if collection_by_id(collection_id) is None:
        raise HTTPException(404, "Unknown collection")

    limit = max(1, min(limit, _MAX_OBJECTS))
    seen = func.coalesce(Entity.last_seen_at, _EPOCH)
    stmt = select(Entity).where(Entity.allowlisted.is_(False))
    if added_after:
        stmt = stmt.where(Entity.last_seen_at > _parse_added_after(added_after))
    if next:
        cursor_seen, cursor_id = _decode_cursor(next)
        stmt = stmt.where(or_(seen < cursor_seen, and_(seen == cursor_seen, Entity.id < cursor_id)))
    rows = (await db.execute(stmt.order_by(seen.desc(), Entity.id.desc()).limit(limit + 1))).scalars().all()
    has_more = len(rows) > limit
    entities = rows[:limit]
    next_cursor = _encode_cursor(entities[-1].last_seen_at, entities[-1].id) if has_more else None
    # The only route here that returns observables rather than metadata, so the only one
    # worth a row. Attributed to the token, which is all a Bearer request carries.
    await activity.record(
        "export.taxii",
        request=request,
        actor_label=f"api token {_token.prefix}",
        target_type="collection",
        target_id=collection_id,
        summary=f"{len(entities)} indicator(s)",
        meta={"collection": collection_id, "count": len(entities)},
    )
    return JSONResponse(
        objects_envelope(entities, more=has_more, next_cursor=next_cursor),
        headers=_STIX_HEADERS,
    )
