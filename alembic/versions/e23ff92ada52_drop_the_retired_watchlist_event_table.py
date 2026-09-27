"""drop the retired watchlist_event table

The nav bell moved to per-user watch rules (`intel_rule_match`) in 0.9.0, and the worker
stopped writing this table at the same time. The table, its writer, its backfill task, its
admin button and its daily prune all survived one release so the change could be rolled
back; nothing ever read a row of it in that time.

**Destructive.** Acknowledged and unacknowledged rows alike are dropped. Nothing surfaced
them, so there is nothing to lose that an operator could have seen — but take the backup
`task upgrade:*` takes anyway. The downgrade recreates the (empty) table.

Revision ID: e23ff92ada52
Revises: 218f0f8db869
Create Date: 2026-08-10 20:51:45.369745
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "e23ff92ada52"
down_revision: Union[str, None] = "218f0f8db869"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("watchlist_event", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_watchlist_event_created_at"))
        batch_op.drop_index(batch_op.f("ix_watchlist_event_entity_id"))
        batch_op.drop_index(batch_op.f("ix_watchlist_event_job_id"))

    op.drop_table("watchlist_event")


def downgrade() -> None:
    op.create_table(
        "watchlist_event",
        sa.Column("id", sa.INTEGER(), nullable=False),
        sa.Column("entity_id", sa.INTEGER(), nullable=False),
        sa.Column("job_id", sa.INTEGER(), nullable=False),
        sa.Column("created_at", sa.DATETIME(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("acknowledged_at", sa.DATETIME(), nullable=True),
        sa.Column("acknowledged_by_user_id", sa.CHAR(length=36), nullable=True),
        sa.ForeignKeyConstraint(
            ["acknowledged_by_user_id"],
            ["user.id"],
        ),
        sa.ForeignKeyConstraint(
            ["entity_id"],
            ["entity.id"],
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["analysisjob.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "job_id", name=op.f("uq_watchlist_event_entity_job")),
    )
    with op.batch_alter_table("watchlist_event", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_watchlist_event_job_id"), ["job_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_watchlist_event_entity_id"), ["entity_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_watchlist_event_created_at"), ["created_at"], unique=False)
