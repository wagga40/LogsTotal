"""job watch webhook flag

Opt one of your watch rules into also delivering your job-watch events, so a job
subscription needs no webhook configuration of its own.

A flag rather than per-`JobWatch` URL/secret columns: those would mean re-entering an
endpoint on every job you follow, a second copy of the SSRF guard and retry backoff to keep
in step, and `webhook_delivery.rule_id` going nullable — which breaks the user-deletion
cleanup.

Revision ID: e0c7d9385a9d
Revises: 7488d95977a1
Create Date: 2026-08-16 14:32:06.061174
"""
from collections.abc import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e0c7d9385a9d'
down_revision: Union[str, None] = '7488d95977a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('intel_rule', schema=None) as batch_op:
        batch_op.add_column(sa.Column('notify_job_watch', sa.Boolean(), server_default='0', nullable=False))



def downgrade() -> None:
    with op.batch_alter_table('intel_rule', schema=None) as batch_op:
        batch_op.drop_column('notify_job_watch')

