"""Add provider prompt limits for jobs and cases; default output to 20000 tokens."""

import sqlalchemy as sa

from alembic import op

revision = "e8a42c97f310"
down_revision = "c63d1e4a902b"
branch_labels = None
depends_on = None


def upgrade():
    # Existing output budgets remain explicit choices. Null prompt limits inherit the
    # instance configuration, including deployments with a non-default character budget.
    with op.batch_alter_table("ai_provider") as batch:
        batch.add_column(sa.Column("job_max_prompt_chars", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("case_max_prompt_chars", sa.Integer(), nullable=True))
        batch.alter_column("max_output_tokens", existing_type=sa.Integer(), existing_nullable=False, server_default="20000")


def downgrade():
    with op.batch_alter_table("ai_provider") as batch:
        batch.alter_column("max_output_tokens", existing_type=sa.Integer(), existing_nullable=False, server_default="4000")
        batch.drop_column("case_max_prompt_chars")
        batch.drop_column("job_max_prompt_chars")
