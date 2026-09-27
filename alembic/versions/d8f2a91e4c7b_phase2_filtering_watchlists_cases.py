"""phase 2: filtering, watchlists, cases — saved searches + watchlist events + cases + entity allowlist

Revision ID: d8f2a91e4c7b
Revises: c5e9a83fb112
Create Date: 2026-05-24 18:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID

from alembic import op

revision: str = "d8f2a91e4c7b"
down_revision: Union[str, None] = "c5e9a83fb112"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("entity", schema=None) as batch_op:
        batch_op.add_column(sa.Column("allowlisted", sa.Boolean(), nullable=False, server_default="0"))
        batch_op.create_index(op.f("ix_entity_allowlisted"), ["allowlisted"], unique=False)

    op.create_table(
        "watchlist_event",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by_user_id", GUID(), nullable=True),
        sa.ForeignKeyConstraint(["entity_id"], ["entity.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.ForeignKeyConstraint(["acknowledged_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "job_id", name="uq_watchlist_event_entity_job"),
    )
    op.create_index(op.f("ix_watchlist_event_entity_id"), "watchlist_event", ["entity_id"], unique=False)
    op.create_index(op.f("ix_watchlist_event_job_id"), "watchlist_event", ["job_id"], unique=False)
    op.create_index(op.f("ix_watchlist_event_created_at"), "watchlist_event", ["created_at"], unique=False)

    op.create_table(
        "investigation_case",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("created_by_user_id", GUID(), nullable=True),
        sa.Column("is_shared", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_investigation_case_status"), "investigation_case", ["status"], unique=False)

    op.create_table(
        "case_entity_link",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("added_by_user_id", GUID(), nullable=True),
        sa.Column("added_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["investigation_case.id"]),
        sa.ForeignKeyConstraint(["entity_id"], ["entity.id"]),
        sa.ForeignKeyConstraint(["added_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "entity_id", name="uq_case_entity"),
    )
    op.create_index(op.f("ix_case_entity_link_case_id"), "case_entity_link", ["case_id"], unique=False)
    op.create_index(op.f("ix_case_entity_link_entity_id"), "case_entity_link", ["entity_id"], unique=False)

    op.create_table(
        "case_job_link",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("added_by_user_id", GUID(), nullable=True),
        sa.Column("added_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["investigation_case.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.ForeignKeyConstraint(["added_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "job_id", name="uq_case_job"),
    )
    op.create_index(op.f("ix_case_job_link_case_id"), "case_job_link", ["case_id"], unique=False)
    op.create_index(op.f("ix_case_job_link_job_id"), "case_job_link", ["job_id"], unique=False)

    op.create_table(
        "saved_search",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("scope", sa.String(length=20), nullable=False, server_default="entities"),
        sa.Column("query_json", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", GUID(), nullable=True),
        sa.Column("is_shared", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_saved_search_created_by_user_id"), "saved_search", ["created_by_user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_saved_search_created_by_user_id"), table_name="saved_search")
    op.drop_table("saved_search")

    op.drop_index(op.f("ix_case_job_link_job_id"), table_name="case_job_link")
    op.drop_index(op.f("ix_case_job_link_case_id"), table_name="case_job_link")
    op.drop_table("case_job_link")

    op.drop_index(op.f("ix_case_entity_link_entity_id"), table_name="case_entity_link")
    op.drop_index(op.f("ix_case_entity_link_case_id"), table_name="case_entity_link")
    op.drop_table("case_entity_link")

    op.drop_index(op.f("ix_investigation_case_status"), table_name="investigation_case")
    op.drop_table("investigation_case")

    op.drop_index(op.f("ix_watchlist_event_created_at"), table_name="watchlist_event")
    op.drop_index(op.f("ix_watchlist_event_job_id"), table_name="watchlist_event")
    op.drop_index(op.f("ix_watchlist_event_entity_id"), table_name="watchlist_event")
    op.drop_table("watchlist_event")

    with op.batch_alter_table("entity", schema=None) as batch_op:
        batch_op.drop_index(op.f("ix_entity_allowlisted"))
        batch_op.drop_column("allowlisted")
