"""Idempotent file submissions and case creation.

Revision ID: f5d18b73a209
Revises: e8a42c97f310
"""

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID

from alembic import op

revision = "f5d18b73a209"
down_revision = "e8a42c97f310"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "submission_receipt",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", GUID(), sa.ForeignKey("user.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(10), nullable=False),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("analysisjob.id", ondelete="SET NULL")),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("investigation_case.id", ondelete="SET NULL")),
        sa.Column("reused", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("user_id", "kind", "key", name="uq_submission_receipt"),
    )


def downgrade() -> None:
    op.drop_table("submission_receipt")
