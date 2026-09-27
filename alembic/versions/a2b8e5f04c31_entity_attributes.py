"""phase B: per-type entity attributes

Revision ID: a2b8e5f04c31
Revises: f1a6d3c8b920
Create Date: 2026-05-30 13:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "a2b8e5f04c31"
down_revision: Union[str, None] = "f1a6d3c8b920"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("entity") as batch_op:
        batch_op.add_column(sa.Column("attributes_json", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("entity") as batch_op:
        batch_op.drop_column("attributes_json")
