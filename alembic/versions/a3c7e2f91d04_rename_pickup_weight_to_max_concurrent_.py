"""rename pickup_weight to max_concurrent_jobs

Revision ID: a3c7e2f91d04
Revises: 1738619d1b88
Create Date: 2026-04-12 14:30:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "a3c7e2f91d04"
down_revision: Union[str, None] = "1738619d1b88"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("worker_policy", schema=None) as batch_op:
        batch_op.add_column(sa.Column("max_concurrent_jobs", sa.Integer(), nullable=False, server_default="0"))
        batch_op.drop_column("pickup_weight")


def downgrade() -> None:
    with op.batch_alter_table("worker_policy", schema=None) as batch_op:
        batch_op.add_column(sa.Column("pickup_weight", sa.Integer(), nullable=False, server_default="100"))
        batch_op.drop_column("max_concurrent_jobs")
