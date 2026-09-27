"""watch rule auto-tags several tags

A rule could auto-tag its matches with exactly one tag, because `action_tag` was
`String(50)`. It now holds the same comma-separated pair of strings the tag picker posts
everywhere else — names, and an index-aligned colour list — parsed by the same
`tags.parse_tag_write`.

Widened in place rather than replaced by a JSON column, and that is the whole point of this
migration being uneventful: an existing single value is already a valid one-element list, so
no data moves and there is no backfill to get wrong. Downgrading truncates, which is why the
down path clamps to the first tag rather than letting the database refuse the change.

Revision ID: b3d51f8a20c7
Revises: e0c7d9385a9d
Create Date: 2026-08-17 13:05:00.000000
"""
from collections.abc import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b3d51f8a20c7'
down_revision: Union[str, None] = 'e0c7d9385a9d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('intel_rule', schema=None) as batch_op:
        batch_op.alter_column('action_tag', existing_type=sa.String(length=50), type_=sa.String(length=500), existing_nullable=True)
        batch_op.alter_column(
            'action_tag_color',
            existing_type=sa.String(length=20),
            type_=sa.String(length=200),
            existing_nullable=False,
            existing_server_default='gray',
        )


def downgrade() -> None:
    # Keep only the first tag and its colour before narrowing, or a rule that had grown a
    # list would fail the column change (PostgreSQL) or be silently truncated mid-name
    # (SQLite), leaving a tag nobody chose.
    op.execute(
        "UPDATE intel_rule SET action_tag = substr(action_tag, 1, instr(action_tag || ',', ',') - 1) "
        "WHERE action_tag IS NOT NULL AND instr(action_tag, ',') > 0"
        if op.get_bind().dialect.name == 'sqlite'
        else "UPDATE intel_rule SET action_tag = split_part(action_tag, ',', 1) WHERE action_tag LIKE '%,%'"
    )
    op.execute(
        "UPDATE intel_rule SET action_tag_color = substr(action_tag_color, 1, instr(action_tag_color || ',', ',') - 1) "
        "WHERE instr(action_tag_color, ',') > 0"
        if op.get_bind().dialect.name == 'sqlite'
        else "UPDATE intel_rule SET action_tag_color = split_part(action_tag_color, ',', 1) WHERE action_tag_color LIKE '%,%'"
    )
    with op.batch_alter_table('intel_rule', schema=None) as batch_op:
        batch_op.alter_column('action_tag', existing_type=sa.String(length=500), type_=sa.String(length=50), existing_nullable=True)
        batch_op.alter_column(
            'action_tag_color',
            existing_type=sa.String(length=200),
            type_=sa.String(length=20),
            existing_nullable=False,
            existing_server_default='gray',
        )
