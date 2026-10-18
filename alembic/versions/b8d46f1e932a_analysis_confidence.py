"""Persist execution provenance and partial detection results.

Revision ID: b8d46f1e932a
Revises: a76e3b9c214d
"""

import sqlalchemy as sa
from alembic import op

revision = "b8d46f1e932a"
down_revision = "a76e3b9c214d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE taskstatus ADD VALUE IF NOT EXISTS 'PARTIAL'")
    op.add_column("analysisjob", sa.Column("execution_snapshot", sa.Text(), nullable=True))
    op.add_column("taskresult", sa.Column("diagnostics_json", sa.Text(), nullable=True))
    op.add_column("taskresult", sa.Column("execution_snapshot", sa.Text(), nullable=True))


def downgrade() -> None:
    # Older applications cannot deserialize PARTIAL task rows. Preserve their
    # evidence but describe the interrupted analysis using the older vocabulary.
    op.execute("UPDATE taskresult SET status = 'FAILED' WHERE status = 'PARTIAL'")
    with op.batch_alter_table("taskresult") as batch:
        batch.drop_column("execution_snapshot")
        batch.drop_column("diagnostics_json")
    with op.batch_alter_table("analysisjob") as batch:
        batch.drop_column("execution_snapshot")
    # PostgreSQL enum labels cannot be removed without recreating the type.
