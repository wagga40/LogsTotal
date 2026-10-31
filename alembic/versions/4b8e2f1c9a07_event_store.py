"""Event stores: every event of an upload as Parquet, one row per file, log type and builder.

Revision ID: 4b8e2f1c9a07
Revises: 0c7d4e9a2b61
"""

import sqlalchemy as sa

from alembic import op

revision = "4b8e2f1c9a07"
down_revision = "0c7d4e9a2b61"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Tolerant: a start with AUTO_MIGRATE=false has create_all make it from the models.
    if "event_store" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "event_store",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("log_file_id", sa.Integer(), nullable=False),
        sa.Column("log_type", sa.String(length=32), nullable=False),
        sa.Column("builder_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("gen", sa.String(length=64), nullable=True),
        sa.Column("event_count", sa.BigInteger(), nullable=True),
        sa.Column("column_count", sa.Integer(), nullable=True),
        sa.Column("bytes", sa.BigInteger(), nullable=True),
        sa.Column("time_min", sa.DateTime(), nullable=True),
        sa.Column("time_max", sa.DateTime(), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False),
        sa.Column("warnings_json", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("requested_by_job_id", sa.Integer(), nullable=True),
        sa.Column("requested_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("last_accessed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["log_file_id"], ["logfile.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("log_file_id", "log_type", "builder_version", name="uq_event_store_file_type_version"),
    )


def downgrade() -> None:
    op.drop_table("event_store")
