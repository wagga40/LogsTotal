"""add user.theme

Revision ID: b42f91c7e035
Revises: a3c7e2f91d04
Create Date: 2026-04-19 10:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b42f91c7e035"
down_revision: Union[str, None] = "a3c7e2f91d04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.add_column(sa.Column("theme", sa.String(length=20), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("user", schema=None) as batch_op:
        batch_op.drop_column("theme")
