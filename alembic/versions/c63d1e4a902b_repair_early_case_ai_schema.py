"""Repair Case AI schemas created before revision b92a7e13c640 was finalized.

Early installs of that revision lack source_deleted_at and SQLite AUTOINCREMENT.
Inspect both independently: finalized installs already have them, and rebuilding
an AUTOINCREMENT table would discard its history of deleted run IDs.
"""

import sqlalchemy as sa

from alembic import op

revision = "c63d1e4a902b"
down_revision = "b92a7e13c640"
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    missing_column = "source_deleted_at" not in {column["name"] for column in sa.inspect(conn).get_columns("case_ai_analysis")}
    if conn.dialect.name == "sqlite":
        table_sql = conn.scalar(sa.text("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'case_ai_analysis'"))
        if "AUTOINCREMENT" not in table_sql.upper():
            # Batch recreation copies reports and preserves their indexes and FKs.
            with op.batch_alter_table("case_ai_analysis", recreate="always", table_kwargs={"sqlite_autoincrement": True}) as batch:
                if missing_column:
                    batch.add_column(sa.Column("source_deleted_at", sa.DateTime(), nullable=True))
            return
    if missing_column:
        op.add_column("case_ai_analysis", sa.Column("source_deleted_at", sa.DateTime(), nullable=True))


def downgrade():
    # The finalized predecessor already declares both; retain its expected schema.
    pass
