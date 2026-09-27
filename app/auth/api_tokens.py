"""API token authentication for ingestion, jobs, cases, the IOC feed and TAXII.

Tokens are stored as SHA-256 hashes; the plaintext is shown to the admin **once** at creation
time and never re-readable. Each token has an explicit scope list (e.g. `["ioc_feed:read"]`).

Also provides the Fernet wrapper used to encrypt at-rest secrets like
`EnrichmentService.api_token_encrypted`.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_async_session
from app.models import ApiToken, User

_log = logging.getLogger(__name__)


# ── Scopes ────────────────────────────────────────────────────────────────────


KNOWN_SCOPES = ("ioc_feed:read", "taxii:read", "case:read", "case:write", "job:submit", "job:read")


def validate_scopes(raw: list[str]) -> list[str]:
    """Filter incoming scope list down to known scopes, deduped + sorted."""
    return sorted({s for s in raw if s in KNOWN_SCOPES})


# ── Token generation + verification ───────────────────────────────────────────


def generate_token() -> tuple[str, str, str]:
    """Generate a new bearer token. Returns (plaintext, sha256_hex, prefix-8)."""
    raw = "lgt_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    prefix = raw[:8]
    return raw, digest, prefix


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _extract_bearer(request: Request) -> str | None:
    header = request.headers.get("Authorization") or request.headers.get("authorization")
    if not header:
        return None
    parts = header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _bearer_attempted(request: Request) -> bool:
    """Whether the request tried to authenticate with a Bearer token — valid or not.

    Only the Bearer scheme counts. The proxy profile's optional basic auth makes a browser
    resend `Authorization: Basic …` on every request, and Caddy forwards it; that is the
    proxy's credential, not ours, so it must fall through to the cookie session. Treating
    any Authorization header as a failed token made every browser upload behind basic auth
    answer 401 "Invalid bearer token".
    """
    parts = (request.headers.get("authorization") or "").split(None, 1)
    return bool(parts) and parts[0].lower() == "bearer"


def basic_auth_in_front(request: Request) -> bool:
    """Whether this request came through a reverse proxy's HTTP basic auth.

    The app never asks for Basic, so a browser sends it only because something in front
    asked, and the proxy forwards it. Behind one, API tokens cannot authenticate: a request
    carries one Authorization header, and the proxy takes it for its own password. The
    tokens page says so. A proxy that strips the header after checking it reads as no
    proxy, so the page can only err by staying silent.
    """
    schemes = (value.split(None, 1)[:1] for value in request.headers.getlist("authorization"))
    return any(scheme and scheme[0].lower() == "basic" for scheme in schemes)


async def _lookup_token(db: AsyncSession, plaintext: str) -> ApiToken | None:
    digest = hash_token(plaintext)
    row = (await db.execute(select(ApiToken).where(ApiToken.token_hash == digest))).scalar_one_or_none()
    if row is None:
        return None
    now = datetime.now(UTC)
    if row.revoked_at is not None:
        return None
    if row.expires_at is not None and row.expires_at < now.replace(tzinfo=None):
        return None
    if row.created_by_user_id is not None and not await _creator_may_delegate(db, row.created_by_user_id):
        return None
    return row


async def _creator_may_delegate(db: AsyncSession, creator_id) -> bool:
    """A token delegates its creator's access, so it lapses when that access does.

    Deactivating an account, or demoting it below member (no Intel by cookie), must stop
    its tokens too; neither touches the token rows, and re-enabling the account restores
    them. Checked here, in the lookup both dependencies share, so TAXII is covered as well.
    """
    from app.models import User, has_intel_access

    return has_intel_access(await db.get(User, creator_id))


def _has_scope(row: ApiToken, scope: str) -> bool:
    import json as _json

    try:
        scopes = _json.loads(row.scopes_json or "[]")
    except (ValueError, TypeError):
        return False
    return scope in scopes


def require_api_token(scope: str):
    """Dependency factory: returns a FastAPI dependency enforcing `scope` on the bearer token.

    Raises 401 if no/invalid token, 403 if the token lacks the scope.
    Touches `last_used_at` on a successful authn (best-effort).
    """

    async def dep(request: Request, db: AsyncSession = Depends(get_async_session)) -> ApiToken:
        plaintext = _extract_bearer(request)
        if not plaintext:
            raise HTTPException(401, "Bearer token required")
        token = await _lookup_token(db, plaintext)
        if token is None:
            raise HTTPException(401, "Invalid or expired token")
        if not _has_scope(token, scope):
            raise HTTPException(403, f"Token missing required scope: {scope}")
        token.last_used_at = datetime.now(UTC).replace(tzinfo=None)
        try:
            await db.commit()
        except Exception as exc:
            _log.warning("api_token: failed to update last_used_at: %s", exc)
            await db.rollback()
        return token

    return dep


def current_user_or_api_token(scope: str):
    """Dependency factory: accepts a cookie-auth member-or-above OR a Bearer token with `scope`.

    Returns either a User (cookie) or an ApiToken (bearer). Raises 401 if neither is present,
    403 if the cookie user lacks member role or the token lacks the scope.
    """
    from app.auth.users import current_user_optional

    async def dep(
        request: Request,
        db: AsyncSession = Depends(get_async_session),
        user: User | None = Depends(current_user_optional),
    ):
        if user is not None:
            if user.is_superuser or (getattr(user, "role", "") in ("admin", "member")):
                return user
            raise HTTPException(403, "Member-or-above access required")
        plaintext = _extract_bearer(request)
        if not plaintext:
            raise HTTPException(401, "Cookie session or bearer token required")
        token = await _lookup_token(db, plaintext)
        if token is None:
            raise HTTPException(401, "Invalid or expired token")
        if not _has_scope(token, scope):
            raise HTTPException(403, f"Token missing required scope: {scope}")
        token.last_used_at = datetime.now(UTC).replace(tzinfo=None)
        try:
            await db.commit()
        except Exception as exc:
            _log.warning("api_token: failed to update last_used_at: %s", exc)
            await db.rollback()
        return token

    return dep


async def principal_user(db: AsyncSession, principal):
    """The ``User`` whose visibility a request carries.

    ``current_user_or_api_token`` returns two different things, and every caller that
    filters by visibility needs one. A cookie request already *is* a User. A Bearer token
    is a **delegation** of its creator's access and never more, so it resolves to the user
    who minted it — an ``ioc_feed:read`` token cannot reach a private job its creator
    could not. A token whose creator has since been deleted resolves to ``None``, which
    the filters treat as anonymous: public data only.

    Lives here, beside the dependency that produces the principal, so the token→viewer
    rule is stated once, for cases, the IOC feed and the MITRE layer alike.
    """
    from app.models import User

    if isinstance(principal, User):
        return principal
    creator_id = getattr(principal, "created_by_user_id", None)
    return await db.get(User, creator_id) if creator_id else None


def principal_actor_label(principal, user) -> str | None:
    """The audit-log label for a request made by `principal` on behalf of `user`.

    A cookie request returns None, so `activity.record` derives the email as usual. A token
    request still belongs to its creator (`user` keeps the row's FK), but the label names
    the token: an incident review has to tell "the admin exported this" from "a token did",
    and know which one to revoke.
    """
    if not isinstance(principal, ApiToken):
        return None
    label = f"api token {principal.prefix}"
    if user is not None:
        label = f"{label} for {user.email}"
    return label[:255]


@dataclass
class SubmissionAccess:
    user: User | None
    token: ApiToken | None = None

    def require(self, scope: str) -> None:
        from app.models import has_intel_access

        if self.user is None:
            raise HTTPException(401, "Sign in or supply a bearer token")
        if self.token is not None and not _has_scope(self.token, scope):
            raise HTTPException(403, f"Token missing required scope: {scope}")
        if scope.startswith("case:") and not has_intel_access(self.user):
            raise HTTPException(403, "Member-or-above access required")

    @property
    def actor_label(self):
        return principal_actor_label(self.token, self.user)


def submission_access(scope: str, *, anonymous: bool = False):
    """Upload/read access without imposing Intel membership on ordinary browser users.

    An explicit Bearer header always wins, including an invalid or empty one. Never
    silently submit anonymously (or with the cookie's privileges) after token failure.
    Any other scheme — a reverse proxy's Basic credential — is not a token attempt.
    """
    from app.auth.users import current_user_optional

    async def dep(request: Request, db: AsyncSession = Depends(get_async_session), user=Depends(current_user_optional)):
        token = None
        if _bearer_attempted(request):
            plaintext = _extract_bearer(request)
            token = await _lookup_token(db, plaintext) if plaintext else None
            if token is None or not _has_scope(token, scope):
                raise HTTPException(401 if token is None else 403, "Invalid bearer token or missing required scope")
            user = await principal_user(db, token)
            if user is None:
                raise HTTPException(401, "Token creator no longer exists")
            now = datetime.now(UTC).replace(tzinfo=None)
            if token.last_used_at is None or (now - token.last_used_at).total_seconds() >= 60:
                token.last_used_at = now
                await db.commit()
        access = SubmissionAccess(user, token)
        if not anonymous or user is not None:
            access.require(scope)
        return access

    return dep


# ── At-rest encryption (Fernet) ───────────────────────────────────────────────


def _fernet_key() -> bytes:
    """Derive a Fernet key from the configured secret. Returns urlsafe-base64 bytes."""
    raw = settings.enrichment_encryption_key or settings.secret_key
    if not raw:
        raise RuntimeError("enrichment_encryption_key/secret_key not configured")
    # Fernet wants 32 raw bytes urlsafe-base64-encoded. Derive deterministically from the secret.
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(plaintext: str) -> str:
    """Fernet-encrypt a string. Returns the urlsafe-base64 token as str."""
    f = Fernet(_fernet_key())
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str | None:
    """Reverse of encrypt_secret. Returns None on InvalidToken (e.g. after key rotation)."""
    if not ciphertext:
        return None
    f = Fernet(_fernet_key())
    try:
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        _log.warning("decrypt_secret: invalid token (likely SECRET_KEY rotated): %s", exc)
        return None
