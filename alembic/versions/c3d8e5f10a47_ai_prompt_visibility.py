"""ai runs: keep the sent prompt, behind a site setting

Revision ID: c3d8e5f10a47
Revises: b7e4f2a91c38
Create Date: 2026-08-15 10:05:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "c3d8e5f10a47"
down_revision: Union[str, None] = "b7e4f2a91c38"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("job_ai_analysis", sa.Column("prompt_text", sa.Text(), nullable=True))
    # server_default so existing rows get the on-by-default value; the ORM column carries
    # the same default for new rows. Dropped straight after, the pattern the other
    # SiteSettings migrations use — a server default left in place quietly becomes a second
    # source of truth for what the default is.
    op.add_column("sitesettings", sa.Column("show_ai_prompt", sa.Boolean(), nullable=False, server_default=sa.true()))
    with op.batch_alter_table("sitesettings", schema=None) as batch_op:
        batch_op.alter_column("show_ai_prompt", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("sitesettings", schema=None) as batch_op:
        batch_op.drop_column("show_ai_prompt")
    with op.batch_alter_table("job_ai_analysis", schema=None) as batch_op:
        batch_op.drop_column("prompt_text")
