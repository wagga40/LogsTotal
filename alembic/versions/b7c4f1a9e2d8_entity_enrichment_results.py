"""phase C: live enrichment results + cache ttl

Revision ID: b7c4f1a9e2d8
Revises: a2b8e5f04c31
Create Date: 2026-05-30 14:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b7c4f1a9e2d8"
down_revision: Union[str, None] = "a2b8e5f04c31"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("enrichment_service") as batch_op:
        batch_op.add_column(sa.Column("cache_ttl_seconds", sa.Integer(), nullable=False, server_default="86400"))

    op.create_table(
        "entity_enrichment_result",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("service_id", sa.Integer(), nullable=False),
        sa.Column("response_json", sa.Text(), nullable=True),
        sa.Column("summary_json", sa.Text(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(["entity_id"], ["entity.id"]),
        sa.ForeignKeyConstraint(["service_id"], ["enrichment_service.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "service_id", name="uq_entity_enrichment"),
    )
    op.create_index(op.f("ix_entity_enrichment_result_entity_id"), "entity_enrichment_result", ["entity_id"], unique=False)
    op.create_index(op.f("ix_entity_enrichment_result_service_id"), "entity_enrichment_result", ["service_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_entity_enrichment_result_service_id"), table_name="entity_enrichment_result")
    op.drop_index(op.f("ix_entity_enrichment_result_entity_id"), table_name="entity_enrichment_result")
    op.drop_table("entity_enrichment_result")
    with op.batch_alter_table("enrichment_service") as batch_op:
        batch_op.drop_column("cache_ttl_seconds")
