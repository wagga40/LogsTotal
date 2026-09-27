"""ai job analysis: providers, runs, and the site switch

Revision ID: a4c7e1d90b52
Revises: e23ff92ada52
Create Date: 2026-08-15 09:00:00.000000
"""

from typing import Sequence, Union

import fastapi_users_db_sqlalchemy
import sqlalchemy as sa

from alembic import op

revision: str = "a4c7e1d90b52"
down_revision: Union[str, None] = "e23ff92ada52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_provider",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False, server_default="openai"),
        sa.Column("base_url", sa.String(length=500), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("api_token_encrypted", sa.Text(), nullable=True),
        sa.Column("system_prompt", sa.Text(), nullable=True),
        sa.Column("temperature", sa.Float(), nullable=False, server_default="0.2"),
        sa.Column("max_output_tokens", sa.Integer(), nullable=False, server_default="4000"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(op.f("ix_ai_provider_enabled"), "ai_provider", ["enabled"], unique=False)

    op.create_table(
        "job_ai_analysis",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("provider_id", sa.Integer(), nullable=True),
        sa.Column("provider_name", sa.String(length=80), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column(
            "status",
            sa.Enum("PENDING", "RUNNING", "COMPLETED", "FAILED", name="aianalysisstatus"),
            nullable=False,
        ),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("error_message", sa.String(length=500), nullable=True),
        # GUID(), not CHAR(32): the type renders as UUID on PostgreSQL and CHAR elsewhere,
        # so a hand-written CHAR would build a column the ORM cannot bind on PG.
        sa.Column("requested_by_user_id", fastapi_users_db_sqlalchemy.generics.GUID(), nullable=True),
        sa.Column("prompt_chars", sa.Integer(), nullable=True),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.ForeignKeyConstraint(["provider_id"], ["ai_provider.id"]),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_job_ai_analysis_job_id"), "job_ai_analysis", ["job_id"], unique=False)
    op.create_index(op.f("ix_job_ai_analysis_provider_id"), "job_ai_analysis", ["provider_id"], unique=False)
    op.create_index(op.f("ix_job_ai_analysis_status"), "job_ai_analysis", ["status"], unique=False)
    op.create_index("ix_job_ai_analysis_job_created", "job_ai_analysis", ["job_id", "created_at"], unique=False)

    # False, not true: the tab is meaningless until a provider exists on /admin/ai.
    with op.batch_alter_table("sitesettings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("show_ai_analysis", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("sitesettings", schema=None) as batch_op:
        batch_op.drop_column("show_ai_analysis")

    op.drop_index("ix_job_ai_analysis_job_created", table_name="job_ai_analysis")
    op.drop_index(op.f("ix_job_ai_analysis_status"), table_name="job_ai_analysis")
    op.drop_index(op.f("ix_job_ai_analysis_provider_id"), table_name="job_ai_analysis")
    op.drop_index(op.f("ix_job_ai_analysis_job_id"), table_name="job_ai_analysis")
    op.drop_table("job_ai_analysis")

    op.drop_index(op.f("ix_ai_provider_enabled"), table_name="ai_provider")
    op.drop_table("ai_provider")
