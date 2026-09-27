"""Configurable browser upload selection limit.

Revision ID: a76e3b9c214d
Revises: f5d18b73a209
"""

import sqlalchemy as sa

from alembic import op

revision = "a76e3b9c214d"
down_revision = "f5d18b73a209"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("sitesettings", sa.Column("max_upload_files", sa.Integer(), nullable=False, server_default="50"))


def downgrade() -> None:
    op.drop_column("sitesettings", "max_upload_files")
