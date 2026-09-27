"""add xml_evtx to the logtype enum (Windows event XML exports)

Revision ID: c4f8a1b62e07
Revises: e91b3c04d7fa
Create Date: 2026-08-05 19:00:00.000000
"""

from typing import Sequence, Union

from alembic import op

revision: str = "c4f8a1b62e07"
down_revision: Union[str, None] = "e91b3c04d7fa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite stores Enum columns as VARCHAR — nothing to alter there. PostgreSQL
    # uses a native enum type, which must learn the new member name.
    # ADD VALUE cannot run inside a transaction block, hence autocommit.
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE logtype ADD VALUE IF NOT EXISTS 'XML_EVTX'")


def downgrade() -> None:
    # PostgreSQL enums cannot drop values; the extra member is harmless. No-op.
    pass
