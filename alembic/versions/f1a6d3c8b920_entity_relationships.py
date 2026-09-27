"""phase A: typed entity relationships

Revision ID: f1a6d3c8b920
Revises: e4a7b8c192d6
Create Date: 2026-05-30 12:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "f1a6d3c8b920"
down_revision: Union[str, None] = "e4a7b8c192d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "entity_relationship",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source_entity_id", sa.Integer(), nullable=False),
        sa.Column("target_entity_id", sa.Integer(), nullable=False),
        sa.Column("relationship_type", sa.String(length=40), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["source_entity_id"], ["entity.id"]),
        sa.ForeignKeyConstraint(["target_entity_id"], ["entity.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_entity_id", "target_entity_id", "relationship_type", name="uq_entity_relationship"),
    )
    op.create_index(op.f("ix_entity_relationship_source_entity_id"), "entity_relationship", ["source_entity_id"], unique=False)
    op.create_index(op.f("ix_entity_relationship_target_entity_id"), "entity_relationship", ["target_entity_id"], unique=False)
    op.create_index(op.f("ix_entity_relationship_relationship_type"), "entity_relationship", ["relationship_type"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_entity_relationship_relationship_type"), table_name="entity_relationship")
    op.drop_index(op.f("ix_entity_relationship_target_entity_id"), table_name="entity_relationship")
    op.drop_index(op.f("ix_entity_relationship_source_entity_id"), table_name="entity_relationship")
    op.drop_table("entity_relationship")
