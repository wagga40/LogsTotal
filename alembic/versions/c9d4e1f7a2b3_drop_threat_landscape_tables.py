"""drop Threat Landscape tables (threat_indicator + threat_indicator_job_link)

Revision ID: c9d4e1f7a2b3
Revises: b7c4f1a9e2d8
Create Date: 2026-06-13 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "c9d4e1f7a2b3"
down_revision: Union[str, None] = "b7c4f1a9e2d8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop the FK-child table first, then the parent.
    op.drop_index(op.f("ix_threat_indicator_job_link_job_id"), table_name="threat_indicator_job_link")
    op.drop_index(op.f("ix_threat_indicator_job_link_indicator_id"), table_name="threat_indicator_job_link")
    op.drop_table("threat_indicator_job_link")
    op.drop_index(op.f("ix_threat_indicator_category_key"), table_name="threat_indicator")
    op.drop_table("threat_indicator")


def downgrade() -> None:
    # Recreate the tables exactly as defined in the initial schema (09db4ba71a7c).
    op.create_table(
        "threat_indicator",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("category_key", sa.String(length=50), nullable=False),
        sa.Column("tag", sa.String(length=200), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("job_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("category_key", "tag", name="uq_threat_indicator_cat_tag"),
    )
    op.create_index(op.f("ix_threat_indicator_category_key"), "threat_indicator", ["category_key"], unique=False)
    op.create_table(
        "threat_indicator_job_link",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("indicator_id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["indicator_id"],
            ["threat_indicator.id"],
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["analysisjob.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator_id", "job_id", name="uq_threat_indicator_job"),
    )
    op.create_index(op.f("ix_threat_indicator_job_link_indicator_id"), "threat_indicator_job_link", ["indicator_id"], unique=False)
    op.create_index(op.f("ix_threat_indicator_job_link_job_id"), "threat_indicator_job_link", ["job_id"], unique=False)
