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
    conn = op.get_bind()
    if conn.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE taskstatus ADD VALUE IF NOT EXISTS 'PARTIAL'")
    # A start with AUTO_MIGRATE=false adds these through the legacy column patcher
    # (database._migrate_analysis_confidence); the next migrating start must not then
    # refuse to boot on a duplicate column.
    inspector = sa.inspect(conn)
    for table, column in (("analysisjob", "execution_snapshot"), ("taskresult", "diagnostics_json"), ("taskresult", "execution_snapshot")):
        if column not in {c["name"] for c in inspector.get_columns(table)}:
            op.add_column(table, sa.Column(column, sa.Text(), nullable=True))


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
