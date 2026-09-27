"""sitesettings.show_process_tree

Revision ID: e7b2c4a91f38
Revises: d3f8a1c52e47
Create Date: 2026-06-28 10:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "e7b2c4a91f38"
down_revision: Union[str, None] = "d3f8a1c52e47"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("sitesettings", schema=None) as batch_op:
        batch_op.add_column(sa.Column("show_process_tree", sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    with op.batch_alter_table("sitesettings", schema=None) as batch_op:
        batch_op.drop_column("show_process_tree")
