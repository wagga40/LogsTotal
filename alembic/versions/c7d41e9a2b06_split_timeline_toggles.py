"""split the two timeline toggles

One `show_event_timeline` flag gated both the hourly activity histogram and the zoomable
per-alert timeline, so an operator could not keep one and drop the other — which is a large
part of why the two read as one redundant feature stacked on itself.

`show_event_timeline` keeps its original meaning (the histogram, which it gated before the
alert timeline existed) and `show_alert_timeline` is new. It defaults to True and is
backfilled from the existing flag, so an instance that had timelines switched off stays
switched off across the upgrade rather than silently gaining a panel.

Revision ID: c7d41e9a2b06
Revises: f2b9c4a71e08
Create Date: 2026-08-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c7d41e9a2b06"
down_revision = "f2b9c4a71e08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # server_default so the NOT NULL holds for the rows that already exist; the ORM-side
    # default keeps new rows correct without it.
    with op.batch_alter_table("sitesettings") as batch:
        batch.add_column(sa.Column("show_alert_timeline", sa.Boolean(), nullable=False, server_default=sa.true()))

    # Carry the old combined choice forward: someone who turned timelines off meant both.
    op.execute("UPDATE sitesettings SET show_alert_timeline = show_event_timeline")


def downgrade() -> None:
    with op.batch_alter_table("sitesettings") as batch:
        batch.drop_column("show_alert_timeline")
