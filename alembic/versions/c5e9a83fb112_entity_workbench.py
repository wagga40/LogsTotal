"""entity workbench: watchlist, notes, tags, finding-entity links

Revision ID: c5e9a83fb112
Revises: b42f91c7e035
Create Date: 2026-05-24 12:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID

from alembic import op

revision: str = "c5e9a83fb112"
down_revision: Union[str, None] = "b42f91c7e035"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("entity", schema=None) as batch_op:
        batch_op.add_column(sa.Column("watchlist", sa.Boolean(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("notes", sa.Text(), nullable=True))
        batch_op.create_index(op.f("ix_entity_watchlist"), ["watchlist"], unique=False)

    op.create_table(
        "entity_tag",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("tag", sa.String(length=50), nullable=False),
        sa.Column("color", sa.String(length=20), nullable=False, server_default="gray"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("created_by_user_id", GUID(), nullable=True),
        sa.ForeignKeyConstraint(["entity_id"], ["entity.id"]),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "tag", name="uq_entity_tag"),
    )
    op.create_index(op.f("ix_entity_tag_entity_id"), "entity_tag", ["entity_id"], unique=False)

    op.create_table(
        "finding_entity_link",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"]),
        sa.ForeignKeyConstraint(["entity_id"], ["entity.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "entity_id", name="uq_finding_entity"),
    )
    op.create_index(op.f("ix_finding_entity_link_finding_id"), "finding_entity_link", ["finding_id"], unique=False)
    op.create_index(op.f("ix_finding_entity_link_entity_id"), "finding_entity_link", ["entity_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_entity_link_entity_id"), table_name="finding_entity_link")
    op.drop_index(op.f("ix_finding_entity_link_finding_id"), table_name="finding_entity_link")
    op.drop_table("finding_entity_link")

    op.drop_index(op.f("ix_entity_tag_entity_id"), table_name="entity_tag")
    op.drop_table("entity_tag")

    with op.batch_alter_table("entity", schema=None) as batch_op:
        batch_op.drop_index(op.f("ix_entity_watchlist"))
        batch_op.drop_column("notes")
        batch_op.drop_column("watchlist")
