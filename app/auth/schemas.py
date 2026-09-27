"""Pydantic schemas for user read/create/update exposed by the auth API."""

import uuid

from fastapi_users import schemas
from pydantic import Field

# `user.display_name` is String(100); PostgreSQL refuses a longer value at commit.
DISPLAY_NAME_MAX = 100


class UserRead(schemas.BaseUser[uuid.UUID]):
    """Schema returned when reading a user."""

    display_name: str | None = None
    role: str


class UserCreate(schemas.BaseUserCreate):
    """Schema for creating a new user."""

    display_name: str | None = Field(default=None, max_length=DISPLAY_NAME_MAX)
    role: str = "user"


class UserUpdate(schemas.BaseUserUpdate):
    """Schema for updating user fields.

    ``role`` is intentionally NOT exposed here. fastapi-users' self-service
    ``PATCH /api/users/me`` calls ``update(safe=True)``, which only strips the
    base sensitive fields (``is_superuser``/``is_active``/``is_verified``) and
    would otherwise let any authenticated user set ``role`` and escalate to
    ``member``/``admin``. Role changes go through the superuser-only
    ``/admin/users/{id}/change-role`` handler, which sets ``role`` and
    ``is_superuser`` together.
    """

    display_name: str | None = Field(default=None, max_length=DISPLAY_NAME_MAX)
