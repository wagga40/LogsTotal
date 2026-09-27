"""events timeline: analysisjob.event_markers

Revision ID: a3d7f01c9b52
Revises: c4f8a1b62e07
Create Date: 2026-08-06 09:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "a3d7f01c9b52"
down_revision: Union[str, None] = "c4f8a1b62e07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Nullable on purpose: pre-upgrade jobs have no index, and the endpoint reports
    # ``index_missing`` for them rather than erroring. ``backfill_analytics`` fills them in.
    with op.batch_alter_table("analysisjob", schema=None) as batch_op:
        batch_op.add_column(sa.Column("event_markers", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("analysisjob", schema=None) as batch_op:
        batch_op.drop_column("event_markers")
