"""rule lists can be fetched from a URL

A list can name a `source_url` and a refresh interval; `refresh_rule_lists_periodic`
re-fetches the ones that are due and records how it went.

Hand-trimmed. Autogenerate also proposed dropping nine indexes and rewriting
`intel_rule.builtin_key`'s unique constraint — drift between one developer's database and
the models, not part of this change. Applying it would have silently dropped
`ix_entity_value` and `ix_entity_type` on every deployment that ran it.

Revision ID: 59aefc585fb3
Revises: c5d2e8f1a9b4
Create Date: 2026-09-06 21:21:25.096889
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "59aefc585fb3"
down_revision: Union[str, None] = "c5d2e8f1a9b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("rule_list", schema=None) as batch_op:
        batch_op.add_column(sa.Column("source_url", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("refresh_hours", sa.Integer(), server_default="0", nullable=False))
        batch_op.add_column(sa.Column("last_fetched_at", sa.DateTime(), nullable=True))
        # Tri-state: NULL is "never tried", which is not "tried and failed".
        batch_op.add_column(sa.Column("last_fetch_ok", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("last_fetch_error", sa.String(length=300), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("rule_list", schema=None) as batch_op:
        batch_op.drop_column("last_fetch_error")
        batch_op.drop_column("last_fetch_ok")
        batch_op.drop_column("last_fetched_at")
        batch_op.drop_column("refresh_hours")
        batch_op.drop_column("source_url")
