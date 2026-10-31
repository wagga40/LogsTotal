"""sitesettings.show_explore and explore_build_enabled

Revision ID: 9d2e6b1f4c58
Revises: 4b8e2f1c9a07
Create Date: 2026-10-31 19:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "9d2e6b1f4c58"
down_revision: Union[str, None] = "4b8e2f1c9a07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The legacy patcher (app/database.py) adds both on an AUTO_MIGRATE=false start; a later
    # migrating start must then skip them, or it refuses to boot on a duplicate column.
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("sitesettings")}
    missing = [name for name in ("show_explore", "explore_build_enabled") if name not in existing]
    if not missing:
        return
    with op.batch_alter_table("sitesettings", schema=None) as batch_op:
        for name in missing:
            batch_op.add_column(sa.Column(name, sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    with op.batch_alter_table("sitesettings", schema=None) as batch_op:
        batch_op.drop_column("explore_build_enabled")
        batch_op.drop_column("show_explore")
