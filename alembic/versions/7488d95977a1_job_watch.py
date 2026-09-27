"""job watch

Subscribe to a job and be told when a comment, an AI analysis or a tag lands on it.

A pair of tables rather than a widening of `intel_rule_match`, and the reason is that
table's unique constraint: `uq_intel_rule_match(rule_id, entity_id, job_id)` is what makes
alerts idempotent, and both SQLite and PostgreSQL treat NULL as distinct in a UNIQUE index
— so a nullable `entity_id` would let `(5, NULL, 42)` insert without limit, for exactly the
new rows and nowhere else.

`job_watch_event.ref_id` is deliberately not a foreign key: it points at whatever caused
the event, and those can be deleted while the event should survive as "this happened".

Revision ID: 7488d95977a1
Revises: 8b5d1d21e8f8
Create Date: 2026-08-16 14:12:05.341730
"""
from collections.abc import Sequence
from typing import Union

import fastapi_users_db_sqlalchemy
import sqlalchemy as sa
from alembic import op


revision: str = '7488d95977a1'
down_revision: Union[str, None] = '8b5d1d21e8f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('job_watch',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('job_id', sa.Integer(), nullable=False),
    sa.Column('user_id', fastapi_users_db_sqlalchemy.generics.GUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.ForeignKeyConstraint(['job_id'], ['analysisjob.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('job_id', 'user_id', name='uq_job_watch')
    )
    with op.batch_alter_table('job_watch', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_job_watch_job_id'), ['job_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_job_watch_user_id'), ['user_id'], unique=False)

    op.create_table('job_watch_event',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('watch_id', sa.Integer(), nullable=False),
    sa.Column('job_id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('ref_id', sa.Integer(), nullable=False),
    sa.Column('summary', sa.String(length=200), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['job_id'], ['analysisjob.id'], ),
    sa.ForeignKeyConstraint(['watch_id'], ['job_watch.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('watch_id', 'kind', 'ref_id', name='uq_job_watch_event')
    )
    with op.batch_alter_table('job_watch_event', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_job_watch_event_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_job_watch_event_job_id'), ['job_id'], unique=False)
        batch_op.create_index('ix_job_watch_event_watch_created', ['watch_id', 'created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_job_watch_event_watch_id'), ['watch_id'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('job_watch_event', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_job_watch_event_watch_id'))
        batch_op.drop_index('ix_job_watch_event_watch_created')
        batch_op.drop_index(batch_op.f('ix_job_watch_event_job_id'))
        batch_op.drop_index(batch_op.f('ix_job_watch_event_created_at'))

    op.drop_table('job_watch_event')
    with op.batch_alter_table('job_watch', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_job_watch_user_id'))
        batch_op.drop_index(batch_op.f('ix_job_watch_job_id'))

    op.drop_table('job_watch')
