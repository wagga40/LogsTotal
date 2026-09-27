"""add worker_policy table

Revision ID: 1738619d1b88
Revises: 09db4ba71a7c
Create Date: 2026-04-12 11:11:05.041146
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "1738619d1b88"
down_revision: Union[str, None] = "09db4ba71a7c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "worker_policy",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("hostname", sa.String(length=200), nullable=False),
        sa.Column("pickup_weight", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_worker_policy_hostname"), "worker_policy", ["hostname"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_worker_policy_hostname"), table_name="worker_policy")
    op.drop_table("worker_policy")
