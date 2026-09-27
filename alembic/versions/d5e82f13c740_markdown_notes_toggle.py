"""render notes and comments as markdown, with an off switch

Analyst prose (case notes, entity notes, comment threads) renders as Markdown. The stored
text is unchanged — this is a display setting only — so turning it off restores the
previous plain rendering with nothing lost.

Defaults to True, including for existing rows: prose written as plain text renders
essentially unchanged as Markdown (paragraphs stay paragraphs), so the upgrade is not a
surprise. An instance that dislikes it flips one switch.

Revision ID: d5e82f13c740
Revises: c7d41e9a2b06
Create Date: 2026-08-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d5e82f13c740"
down_revision = "c7d41e9a2b06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("sitesettings") as batch:
        batch.add_column(sa.Column("render_markdown", sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    with op.batch_alter_table("sitesettings") as batch:
        batch.drop_column("render_markdown")
