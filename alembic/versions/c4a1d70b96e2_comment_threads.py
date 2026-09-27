"""comment threads on cases, entities, and jobs

Revision ID: c4a1d70b96e2
Revises: b31de41ae794
Create Date: 2026-08-03 10:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID

from alembic import op

revision: str = "c4a1d70b96e2"
down_revision: Union[str, None] = "b31de41ae794"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "comment",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("entity_id", sa.Integer(), nullable=True),
        sa.Column("job_id", sa.Integer(), nullable=True),
        sa.Column("author_user_id", GUID(), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("edited_at", sa.DateTime(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
        sa.Column("deleted_by_user_id", GUID(), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["investigation_case.id"]),
        sa.ForeignKeyConstraint(["entity_id"], ["entity.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.ForeignKeyConstraint(["author_user_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["deleted_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        # Exactly one target. Mirrors Comment.__table_args__ verbatim.
        sa.CheckConstraint(
            "(CASE WHEN case_id IS NULL THEN 0 ELSE 1 END "
            "+ CASE WHEN entity_id IS NULL THEN 0 ELSE 1 END "
            "+ CASE WHEN job_id IS NULL THEN 0 ELSE 1 END) = 1",
            name="ck_comment_single_target",
        ),
    )
    # Composite index names must byte-match the Index(...) names in the model or
    # test_parity_alembic_head_matches_models fails.
    op.create_index("ix_comment_case_created", "comment", ["case_id", "created_at"], unique=False)
    op.create_index("ix_comment_entity_created", "comment", ["entity_id", "created_at"], unique=False)
    op.create_index("ix_comment_job_created", "comment", ["job_id", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_comment_job_created", table_name="comment")
    op.drop_index("ix_comment_entity_created", table_name="comment")
    op.drop_index("ix_comment_case_created", table_name="comment")
    op.drop_table("comment")
