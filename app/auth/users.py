"""FastAPI-Users setup: user manager, cookie+JWT auth backend, dependency helpers."""

import logging
import uuid

from fastapi import Depends, HTTPException, Request
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin
from fastapi_users.authentication import (
    AuthenticationBackend,
    CookieTransport,
    JWTStrategy,
)
from fastapi_users.exceptions import InvalidPasswordException
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from app import activity
from app.config import settings
from app.database import get_async_session
from app.models import User

logger = logging.getLogger(__name__)

# ── User database dependency ────────────────────────────────────────────────────


async def get_user_db(session: AsyncSession = Depends(get_async_session)):
    yield SQLAlchemyUserDatabase(session, User)


# ── User manager ─────────────────────────────────────────────────────────────────

# Known-default / trivially guessable passwords rejected outright (compared
# case-insensitively). Length < 8 is rejected separately, so only entries with
# 8+ characters matter here — most notably the shipped init default.
WEAK_PASSWORDS = frozenset(
    {
        "changeme",
        "changeme123",
        "password",
        "password1",
        "password123",
        "admin123",
        "administrator",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty123",
        "welcome1",
        "iloveyou",
        "logstotal",
    }
)

PASSWORD_MIN_LENGTH = 8


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = settings.secret_key
    verification_token_secret = settings.secret_key

    async def validate_password(self, password: str, user) -> None:
        """Password policy for every create/update path (init_db, /admin/users, PATCH /api/users/me)."""
        if len(password) < PASSWORD_MIN_LENGTH:
            raise InvalidPasswordException(reason=f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")
        if password.strip().lower() in WEAK_PASSWORDS:
            raise InvalidPasswordException(reason="Password is a known default/common value — choose a stronger one.")
        email = (getattr(user, "email", "") or "").strip().lower()
        if email and email in password.lower():
            raise InvalidPasswordException(reason="Password must not contain the account email.")

    async def authenticate(self, credentials):
        """Record the outcome of a sign-in attempt.

        This is the seam rather than inspecting the login response in middleware, because
        only here is the *attempted account* known — and that identity is the entire value
        of a failed-login record. fastapi-users offers no failure hook: ``super()`` returns
        ``None`` for both an unknown email and a wrong password, and the route separately
        rejects a user who authenticated but is inactive, so the two cases are told apart
        here rather than guessed at from a status code.

        There is no ``Request`` at this layer. The client IP and correlation id arrive
        anyway, through the contextvar ``RequestContextMiddleware`` sets.
        """
        user = await super().authenticate(credentials)
        # Never the password, and never in a way that could echo it: the username only.
        if user is None:
            await activity.record("auth.login_failed", outcome=activity.OUTCOME_FAILURE, summary=credentials.username, actor_label=credentials.username)
        elif not user.is_active:
            await activity.record("auth.login_failed", outcome=activity.OUTCOME_DENIED, summary="account is inactive", actor_user_id=user.id, actor_label=user.email)
        return user

    async def on_after_login(self, user: User, request: Request | None = None, response=None):
        await activity.record("auth.login", request=request, user=user)

    async def on_after_register(self, user: User, request: Request | None = None):
        logger.info("User registered: %s", user.email)
        await activity.record("auth.register", request=request, user=user)

    async def on_after_forgot_password(self, user: User, token: str, request: Request | None = None):
        logger.warning("Password reset requested for user: %s", user.email)
        await activity.record("auth.password_reset_requested", request=request, user=user)


async def get_user_manager(user_db: SQLAlchemyUserDatabase = Depends(get_user_db)):
    yield UserManager(user_db)


# ── Auth backend (cookie + JWT) ─────────────────────────────────────────────────

cookie_transport = CookieTransport(
    cookie_name="logstotal_auth",
    cookie_max_age=86400,  # 24h
    cookie_secure=settings.cookie_secure,
    cookie_httponly=True,
    cookie_samesite="lax",
)


def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(secret=settings.secret_key, lifetime_seconds=86400)


auth_backend = AuthenticationBackend(
    name="cookie",
    transport=cookie_transport,
    get_strategy=get_jwt_strategy,
)

# ── FastAPIUsers instance ────────────────────────────────────────────────────────

fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

current_user_optional = fastapi_users.current_user(optional=True, active=True)
current_user_required = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)

MEMBER_ROLES = {"member", "admin"}


async def user_for_error_page(request: Request) -> User | None:
    """The signed-in user, for the nav of an error page — or None, whatever goes wrong.

    The exception handlers run outside dependency injection, so they used to pass
    `user: None` and every 404 showed a signed-in admin a logged-out nav. This reads the
    same cookie `current_user_optional` does, in its own session; it swallows everything,
    because a 500 is often a database outage and the page reporting it must still render.
    """
    token = request.cookies.get(cookie_transport.cookie_name)
    if not token:
        return None
    try:
        from app import database

        async with database.async_session_maker() as session:
            user = await get_jwt_strategy().read_token(token, UserManager(SQLAlchemyUserDatabase(session, User)))
    except Exception:
        return None
    return user if user is not None and user.is_active else None


async def current_member_or_above(
    user: User = Depends(fastapi_users.current_user(active=True)),
) -> User:
    """Require at least member-level access (member role or superuser)."""
    if user.is_superuser or user.role in MEMBER_ROLES:
        return user
    raise HTTPException(status_code=403, detail="Member access required.")
