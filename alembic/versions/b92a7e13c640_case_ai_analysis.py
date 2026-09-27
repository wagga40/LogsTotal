"""Case AI runs and a provider prompt override for case assessments."""

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "b92a7e13c640"
down_revision = "a72f9b3c610e"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("ai_provider", sa.Column("case_system_prompt", sa.Text(), nullable=True))
    labels = ("PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED")
    status = sa.Enum(*labels, name="aianalysisstatus")
    if op.get_bind().dialect.name == "postgresql":
        status = postgresql.ENUM(*labels, name="aianalysisstatus", create_type=False)
    op.create_table(
        "case_ai_analysis",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.Integer(), sa.ForeignKey("investigation_case.id"), nullable=False),
        sa.Column("provider_id", sa.Integer(), sa.ForeignKey("ai_provider.id")),
        sa.Column("provider_name", sa.String(80), nullable=False),
        sa.Column("model", sa.String(200), nullable=False),
        sa.Column("status", status, nullable=False),
        sa.Column("content", sa.Text()),
        sa.Column("error_message", sa.String(500)),
        sa.Column("log_output", sa.Text()),
        sa.Column("prompt_text", sa.Text()),
        sa.Column("requested_by_user_id", GUID(), sa.ForeignKey("user.id")),
        sa.Column("prompt_chars", sa.Integer()),
        sa.Column("input_tokens", sa.Integer()),
        sa.Column("output_tokens", sa.Integer()),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime()),
        sa.Column("source_jobs_json", sa.Text()),
        sa.Column("source_deleted_at", sa.DateTime()),
        sa.Column("evidence_captured_at", sa.DateTime()),
        sqlite_autoincrement=True,
    )
    for column in ("case_id", "provider_id", "status"):
        op.create_index(f"ix_case_ai_analysis_{column}", "case_ai_analysis", [column])
    op.create_index("ix_case_ai_analysis_case_created", "case_ai_analysis", ["case_id", "created_at"])


def downgrade():
    op.drop_table("case_ai_analysis")
    op.drop_column("ai_provider", "case_system_prompt")
