"""case workspace: case notes + per-link notes

Revision ID: b31de41ae794
Revises: b7c4e92d1a63
Create Date: 2026-07-19 20:32:38.783426
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b31de41ae794"
down_revision: Union[str, None] = "b7c4e92d1a63"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("investigation_case", schema=None) as batch_op:
        batch_op.add_column(sa.Column("notes", sa.Text(), nullable=True))
    with op.batch_alter_table("case_entity_link", schema=None) as batch_op:
        batch_op.add_column(sa.Column("note", sa.String(length=500), nullable=True))
    with op.batch_alter_table("case_job_link", schema=None) as batch_op:
        batch_op.add_column(sa.Column("note", sa.String(length=500), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("case_job_link", schema=None) as batch_op:
        batch_op.drop_column("note")
    with op.batch_alter_table("case_entity_link", schema=None) as batch_op:
        batch_op.drop_column("note")
    with op.batch_alter_table("investigation_case", schema=None) as batch_op:
        batch_op.drop_column("notes")
