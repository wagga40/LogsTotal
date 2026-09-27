"""drop the theme preference

One theme, so there is no preference to store. The second one ("glass", a liquid-glass
treatment) is gone: `backdrop-filter` on every card made each one both a stacking context
and a containing block for `fixed` descendants, which broke dropdown layering and popup
positioning in ways that could not occur in the remaining theme — so every menu had to be
verified twice, and the bugs only ever appeared in one of them.

The column goes rather than being left NULL. The previous theme removal (`f2b9c4a71e08`)
nulled the stored preference and kept the column, which was right while a choice still
existed; with one theme the column can only ever hold a value nothing reads.

The down path recreates it nullable, which is the state a restored database would have been
in anyway — every row's preference is unrecoverable, and inventing one would be worse than
the NULL that means "no preference".

Revision ID: c8f24a1b6d90
Revises: b3d51f8a20c7
Create Date: 2026-08-17 16:05:00.000000
"""
from collections.abc import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c8f24a1b6d90'
down_revision: Union[str, None] = 'b3d51f8a20c7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('theme')


def downgrade() -> None:
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('theme', sa.String(length=20), nullable=True))
