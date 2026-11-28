"""The SQLAlchemy side of fastapi-users: the user table base, its GUID type, the DB adapter.

Adapted from fastapi-users-db-sqlalchemy 7.0.0
(https://github.com/fastapi-users/fastapi-users-db-sqlalchemy), MIT licence,
Copyright (c) 2021 François Voron — see THIRD_PARTY_NOTICES.md.

Inlined rather than depended on because that package is the only thing between this
project and SQLAlchemy 2.1: 7.0.0, still its newest release, declares
`sqlalchemy<2.1.0`. Only what LogsTotal uses is kept — no OAuth account table, no
access-token table, no `TIMESTAMPAware`.

The column definitions, the GUID's storage (PostgreSQL `UUID`, CHAR(36) elsewhere) and the
table name are unchanged, because the database already holds that schema. The Alembic
parity test (tests/test_migrations_auto.py) fails if any of them drifts.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, Generic

from fastapi_users.db.base import BaseUserDatabase
from fastapi_users.models import ID, UP
from sqlalchemy import CHAR, Boolean, String, TypeDecorator, func, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql import Select

UUID_ID = uuid.UUID


class GUID(TypeDecorator):
    """A UUID column: PostgreSQL's native `UUID`, `CHAR(36)` text everywhere else."""

    # The class, not CHAR(36): an instance would make autogenerate render `GUID(length=36)`
    # in every future revision. The length comes from load_dialect_impl, as upstream did.
    impl = CHAR
    cache_ok = True

    @property
    def python_type(self):
        return uuid.UUID

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(UUID())
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return str(value)
        return str(value if isinstance(value, uuid.UUID) else uuid.UUID(value))

    def process_result_value(self, value, dialect):
        if value is None or isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(value)


class SQLAlchemyBaseUserTable(Generic[ID]):
    """The columns fastapi-users reads and writes, on the `user` table."""

    __tablename__ = "user"

    if TYPE_CHECKING:
        id: ID
        email: str
        hashed_password: str
        is_active: bool
        is_superuser: bool
        is_verified: bool
    else:
        email: Mapped[str] = mapped_column(String(length=320), unique=True, index=True, nullable=False)
        hashed_password: Mapped[str] = mapped_column(String(length=1024), nullable=False)
        is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
        is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
        is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class SQLAlchemyBaseUserTableUUID(SQLAlchemyBaseUserTable[UUID_ID]):
    if TYPE_CHECKING:
        id: UUID_ID
    else:
        id: Mapped[UUID_ID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)


class SQLAlchemyUserDatabase(Generic[UP, ID], BaseUserDatabase[UP, ID]):
    """fastapi-users' database protocol over an async SQLAlchemy session."""

    def __init__(self, session: AsyncSession, user_table: type[UP]):
        self.session = session
        self.user_table = user_table

    async def get(self, id: ID) -> UP | None:
        return await self._get_user(select(self.user_table).where(self.user_table.id == id))

    async def get_by_email(self, email: str) -> UP | None:
        return await self._get_user(select(self.user_table).where(func.lower(self.user_table.email) == func.lower(email)))

    async def create(self, create_dict: dict[str, Any]) -> UP:
        user = self.user_table(**create_dict)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def update(self, user: UP, update_dict: dict[str, Any]) -> UP:
        for key, value in update_dict.items():
            setattr(user, key, value)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def delete(self, user: UP) -> None:
        await self.session.delete(user)
        await self.session.commit()

    async def _get_user(self, statement: Select) -> UP | None:
        results = await self.session.execute(statement)
        return results.unique().scalar_one_or_none()
