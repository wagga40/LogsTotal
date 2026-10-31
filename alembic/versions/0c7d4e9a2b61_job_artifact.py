"""Per-job derived results computed once in the analytics pass (job_artifact).

The case timeline's hourly buckets and the process forest were caches over the raw tool
outputs, rebuilt on every miss (2.5 s + 0.9 s and about 1 GB of RSS for one development
job) and lost with the outputs at JOB_OUTPUT_RETENTION_DAYS. Stored per job, compressed.

Revision ID: 0c7d4e9a2b61
Revises: f3a91c2e7d40
"""

import sqlalchemy as sa

from alembic import op

revision = "0c7d4e9a2b61"
down_revision = "f3a91c2e7d40"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Tolerant: a start with AUTO_MIGRATE=false has create_all make it from the models.
    if "job_artifact" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "job_artifact",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", "kind", name="uq_job_artifact"),
    )


def downgrade() -> None:
    op.drop_table("job_artifact")
