"""add linux log types (journald, sysmon_linux) to the logtype enum

Revision ID: a9e3d17c5f42
Revises: e7b2c4a91f38
Create Date: 2026-07-19 10:00:00.000000
"""

from typing import Sequence, Union

from alembic import op

revision: str = "a9e3d17c5f42"
down_revision: Union[str, None] = "e7b2c4a91f38"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite stores Enum columns as VARCHAR — nothing to alter there. PostgreSQL
    # uses a native enum type, which must learn the new member names.
    # ADD VALUE cannot run inside a transaction block, hence autocommit.
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE logtype ADD VALUE IF NOT EXISTS 'JOURNALD'")
            op.execute("ALTER TYPE logtype ADD VALUE IF NOT EXISTS 'SYSMON_LINUX'")


def downgrade() -> None:
    # PostgreSQL enums cannot drop values; the extra members are harmless. No-op.
    pass
