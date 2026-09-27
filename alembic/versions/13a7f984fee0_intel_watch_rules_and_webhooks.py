"""intel watch rules and webhooks

Adds the per-user detection layer: `intel_rule` (criteria + actions), `intel_rule_match`
(the alert, idempotent per rule/entity/job) and `webhook_delivery` (an attempt log the rule
owner can debug against).

Purely additive. `watchlist_event` and `Entity.watchlist` are left untouched: the flag is
still the shared team marker used by the graph, GraphML, the IOC feed and the dashboard
sort, and keeping the old alert table dormant for a release preserves a rollback path.

NOTE: alembic autogenerate also proposed dropping ix_analysisjob_*, ix_backgroundtask_*,
ix_entity_type, ix_entity_value and ix_finding_rule_sig_id. Those are created by
`app/database.py` outside the ORM metadata, so they look like drift to `compare_metadata`
but are load-bearing in production. They are deliberately not dropped here.

Revision ID: 13a7f984fee0
Revises: a3d7f01c9b52
Create Date: 2026-08-07 10:45:46.067420
"""

from typing import Sequence, Union

import fastapi_users_db_sqlalchemy
import sqlalchemy as sa

from alembic import op

revision: str = "13a7f984fee0"
down_revision: Union[str, None] = "a3d7f01c9b52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "intel_rule",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("owner_user_id", fastapi_users_db_sqlalchemy.generics.GUID(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("query", sa.String(length=500), server_default="", nullable=False),
        sa.Column("entity_types", sa.Text(), server_default="[]", nullable=False),
        sa.Column("action_tag", sa.String(length=50), nullable=True),
        sa.Column("action_tag_color", sa.String(length=20), server_default="gray", nullable=False),
        sa.Column("action_notify", sa.Boolean(), server_default="1", nullable=False),
        sa.Column("webhook_url", sa.String(length=500), nullable=True),
        sa.Column("webhook_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("webhook_enabled", sa.Boolean(), server_default="0", nullable=False),
        sa.Column("auto_entity_id", sa.Integer(), nullable=True),
        sa.Column("last_evaluated_at", sa.DateTime(), nullable=True),
        sa.Column("last_matched_at", sa.DateTime(), nullable=True),
        sa.Column("match_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["auto_entity_id"], ["entity.id"]),
        sa.ForeignKeyConstraint(["owner_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_user_id", "auto_entity_id", name="uq_intel_rule_auto_entity"),
    )
    with op.batch_alter_table("intel_rule", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_intel_rule_auto_entity_id"), ["auto_entity_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_intel_rule_enabled"), ["enabled"], unique=False)
        batch_op.create_index("ix_intel_rule_enabled_owner", ["enabled", "owner_user_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_intel_rule_owner_user_id"), ["owner_user_id"], unique=False)

    op.create_table(
        "intel_rule_match",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by_user_id", fastapi_users_db_sqlalchemy.generics.GUID(), nullable=True),
        sa.ForeignKeyConstraint(["acknowledged_by_user_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["entity_id"], ["entity.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.ForeignKeyConstraint(["rule_id"], ["intel_rule.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id", "entity_id", "job_id", name="uq_intel_rule_match"),
    )
    with op.batch_alter_table("intel_rule_match", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_intel_rule_match_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_intel_rule_match_entity_id"), ["entity_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_intel_rule_match_job_id"), ["job_id"], unique=False)
        batch_op.create_index("ix_intel_rule_match_rule_created", ["rule_id", "created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_intel_rule_match_rule_id"), ["rule_id"], unique=False)

    op.create_table(
        "webhook_delivery",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=True),
        sa.Column("match_count", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("error_message", sa.String(length=300), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.ForeignKeyConstraint(["rule_id"], ["intel_rule.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("webhook_delivery", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_webhook_delivery_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_webhook_delivery_job_id"), ["job_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_webhook_delivery_ok"), ["ok"], unique=False)
        batch_op.create_index(batch_op.f("ix_webhook_delivery_rule_id"), ["rule_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("webhook_delivery", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_webhook_delivery_rule_id"))
        batch_op.drop_index(batch_op.f("ix_webhook_delivery_ok"))
        batch_op.drop_index(batch_op.f("ix_webhook_delivery_job_id"))
        batch_op.drop_index(batch_op.f("ix_webhook_delivery_created_at"))
    op.drop_table("webhook_delivery")

    with op.batch_alter_table("intel_rule_match", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_intel_rule_match_rule_id"))
        batch_op.drop_index("ix_intel_rule_match_rule_created")
        batch_op.drop_index(batch_op.f("ix_intel_rule_match_job_id"))
        batch_op.drop_index(batch_op.f("ix_intel_rule_match_entity_id"))
        batch_op.drop_index(batch_op.f("ix_intel_rule_match_created_at"))
    op.drop_table("intel_rule_match")

    with op.batch_alter_table("intel_rule", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_intel_rule_owner_user_id"))
        batch_op.drop_index("ix_intel_rule_enabled_owner")
        batch_op.drop_index(batch_op.f("ix_intel_rule_enabled"))
        batch_op.drop_index(batch_op.f("ix_intel_rule_auto_entity_id"))
    op.drop_table("intel_rule")
