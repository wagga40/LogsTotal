"""entity_relationship_evidence: per-job provenance for relationship edges

Revision ID: d3f8a1c52e47
Revises: c9d4e1f7a2b3
Create Date: 2026-06-20 12:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "d3f8a1c52e47"
down_revision: Union[str, None] = "c9d4e1f7a2b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "entity_relationship_evidence",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("relationship_id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("sample_events_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["relationship_id"], ["entity_relationship.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("relationship_id", "job_id", name="uq_relationship_evidence"),
    )
    op.create_index(op.f("ix_entity_relationship_evidence_relationship_id"), "entity_relationship_evidence", ["relationship_id"], unique=False)
    op.create_index(op.f("ix_entity_relationship_evidence_job_id"), "entity_relationship_evidence", ["job_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_entity_relationship_evidence_job_id"), table_name="entity_relationship_evidence")
    op.drop_index(op.f("ix_entity_relationship_evidence_relationship_id"), table_name="entity_relationship_evidence")
    op.drop_table("entity_relationship_evidence")
