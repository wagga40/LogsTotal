"""add cancelled to the jobstatus and taskstatus enums

Revision ID: b7c4e92d1a63
Revises: a9e3d17c5f42
Create Date: 2026-07-19 12:00:00.000000
"""

from typing import Sequence, Union

from alembic import op

revision: str = "b7c4e92d1a63"
down_revision: Union[str, None] = "a9e3d17c5f42"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite stores Enum columns as VARCHAR — nothing to alter there. PostgreSQL
    # uses native enum types, which must learn the new member name.
    # ADD VALUE cannot run inside a transaction block, hence autocommit.
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE jobstatus ADD VALUE IF NOT EXISTS 'CANCELLED'")
            op.execute("ALTER TYPE taskstatus ADD VALUE IF NOT EXISTS 'CANCELLED'")


def downgrade() -> None:
    # PostgreSQL enums cannot drop values; the extra member is harmless. No-op.
    pass
